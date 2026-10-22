//! Tests of the remote-mode collector runtime against an in-process
//! Giganto-like QUIC server.
//!
//! The server completes giganto-client's handshake with a configurable
//! version requirement, verifies client certificates against an rcgen CA,
//! and reads every stream's record header and batches. It sends a data ACK
//! for every record and the close ACK for every close marker, unless told to
//! withhold the data ACKs or the close ACK, or to hold data ACKs back and send
//! them later, and can stop reading a kind's streams, stop a stream or close a
//! connection.

mod support;

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use anyhow::{Context, Result};
use giganto_client::{
    RawEventKind, connection::server_handshake, frame::recv_raw, ingest::log::Log,
    ingest::receive_record_header,
};
use quinn::{Endpoint, RecvStream, SendStream, VarInt};
use reproduce::config::remote::{CollectorConfig, CollectorType, RemoteConfig, StartPosition};
use reproduce::manager::{ConfigRuntime, TlsFiles};
use reproduce::reload::ReloadSignal;
use reproduce::runtime::CollectorRuntime;
use reproduce::sender::CHANNEL_CLOSE_TIMESTAMP;
use support::{Files, Identity, Logs, Pki, SERVER_NAME, server_config_trusting};
use tempfile::TempDir;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep, timeout};
use tokio_util::sync::CancellationToken;

/// The retry interval the runtime is built with.
const RETRY: Duration = Duration::from_millis(200);
/// How long a test waits for something that should happen.
const WAIT: Duration = Duration::from_secs(30);
/// How long a test waits to show that something does not happen.
const SETTLE: Duration = Duration::from_millis(1500);
/// The runtime's deadline for closing streams.
const CLOSE_DEADLINE: Duration = Duration::from_secs(15);
/// The version requirement Giganto 0.31.0 accepts.
const GIGANTO_VERSION_REQ: &str = ">=0.28.0";

/// Whose close ACKs the server withholds.
#[derive(Clone, Debug, Default)]
enum Withhold {
    #[default]
    Nothing,
    All,
    Kinds(HashSet<String>),
}

impl Withhold {
    fn holds(&self, kind: Option<&str>) -> bool {
        match self {
            Self::Nothing => false,
            Self::All => true,
            Self::Kinds(kinds) => kind.is_some_and(|kind| kinds.contains(kind)),
        }
    }
}

/// One stream the server accepted.
#[derive(Clone, Debug)]
struct StreamRecord {
    connection: usize,
    header: u32,
    accepted_at: Instant,
    /// `(kind, line)` of every `Log` record received.
    records: Vec<(String, String)>,
    /// The timestamp of every `Log` record received.
    timestamps: Vec<i64>,
    close_marker: bool,
    /// How the stream ended, if it has.
    ended: Option<String>,
    stop: CancellationToken,
}

impl StreamRecord {
    fn kind(&self) -> Option<&str> {
        self.records.first().map(|(kind, _)| kind.as_str())
    }

    fn lines(&self) -> Vec<String> {
        self.records.iter().map(|(_, line)| line.clone()).collect()
    }
}

struct GigantoState {
    version_req: Mutex<String>,
    withhold: watch::Sender<Withhold>,
    /// The kinds whose data ACKs are withheld; their records are still
    /// stored.
    withhold_acks: Mutex<HashSet<String>>,
    /// When a connection failed before its Giganto handshake, as a TLS
    /// refusal does.
    refused: Mutex<Vec<Instant>>,
    /// When a Giganto handshake was refused.
    version_refused: Mutex<Vec<Instant>>,
    connections: Mutex<Vec<quinn::Connection>>,
    streams: Mutex<Vec<StreamRecord>>,
    /// How many new streams to stop as soon as their header arrives.
    stop_next: Mutex<usize>,
    /// The data ACKs held back to be sent later.
    hold: tokio::sync::Mutex<Hold>,
    /// The send side of every stream, by its index, until it ends.
    senders: Mutex<Vec<Option<Arc<tokio::sync::Mutex<SendStream>>>>>,
    /// `(kind, line)`: the record after which the kind's streams are read
    /// no further.
    pause_after: Mutex<Option<(String, String)>>,
    /// The kinds whose streams are read no further; their ACKs can still be
    /// sent.
    paused: watch::Sender<HashSet<String>>,
}

/// Data ACKs held back, sent later in order on their streams.
#[derive(Default)]
struct Hold {
    kinds: HashSet<String>,
    /// `(stream index, timestamp)`, oldest first.
    acks: Vec<(usize, i64)>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().expect("lock")
}

/// An in-process Giganto ingest server.
struct Giganto {
    addr: SocketAddr,
    endpoint: Endpoint,
    state: Arc<GigantoState>,
    task: JoinHandle<()>,
}

impl Giganto {
    fn start(pki: &Pki) -> Result<Self> {
        let config = server_config_trusting(&pki.server, &pki.ca)?;
        let endpoint =
            Endpoint::server(config, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))?;
        let addr = endpoint.local_addr()?;
        let state = Arc::new(GigantoState {
            version_req: Mutex::new(GIGANTO_VERSION_REQ.to_string()),
            withhold: watch::channel(Withhold::Nothing).0,
            withhold_acks: Mutex::new(HashSet::new()),
            refused: Mutex::new(Vec::new()),
            version_refused: Mutex::new(Vec::new()),
            connections: Mutex::new(Vec::new()),
            streams: Mutex::new(Vec::new()),
            stop_next: Mutex::new(0),
            hold: tokio::sync::Mutex::new(Hold::default()),
            senders: Mutex::new(Vec::new()),
            pause_after: Mutex::new(None),
            paused: watch::channel(HashSet::new()).0,
        });
        let task = tokio::spawn(accept(endpoint.clone(), state.clone()));
        Ok(Self {
            addr,
            endpoint,
            state,
            task,
        })
    }

    /// Verifies client certificates against `client_ca` from now on.
    fn trust(&self, server: &Identity, client_ca: &str) -> Result<()> {
        self.endpoint
            .set_server_config(Some(server_config_trusting(server, client_ca)?));
        Ok(())
    }

    fn set_version_req(&self, version_req: &str) {
        *lock(&self.state.version_req) = version_req.to_string();
    }

    fn withhold(&self, withhold: Withhold) {
        self.state.withhold.send_replace(withhold);
    }

    /// Withholds the data ACKs of `kinds` from now on, and only theirs.
    fn withhold_acks(&self, kinds: &[&str]) {
        *lock(&self.state.withhold_acks) = kinds.iter().map(|kind| (*kind).to_string()).collect();
    }

    /// Holds back the data ACKs of `kinds` from now on, to be sent by
    /// [`release_acks`](Self::release_acks).
    async fn hold_acks(&self, kinds: &[&str]) {
        self.state.hold.lock().await.kinds = kinds.iter().map(|kind| (*kind).to_string()).collect();
    }

    /// Sends every held data ACK, in order, on the stream it is for, and
    /// holds nothing back any more.
    async fn release_acks(&self) {
        let mut hold = self.state.hold.lock().await;
        hold.kinds.clear();
        for (index, timestamp) in std::mem::take(&mut hold.acks) {
            let send = lock(&self.state.senders)[index].clone();
            if let Some(send) = send {
                let _ = send.lock().await.write_all(&timestamp.to_be_bytes()).await;
            }
        }
    }

    /// Reads no further frame of the streams of `kind` once a frame with
    /// the record `line` of `kind` was read, until
    /// [`resume_reading`](Self::resume_reading). Held ACKs can still be
    /// released meanwhile.
    fn pause_reading_after(&self, kind: &str, line: &str) {
        *lock(&self.state.pause_after) = Some((kind.to_string(), line.to_string()));
    }

    /// Reads every stream again.
    fn resume_reading(&self) {
        *lock(&self.state.pause_after) = None;
        self.state.paused.send_replace(HashSet::new());
    }

    fn stop_next_streams(&self, count: usize) {
        *lock(&self.state.stop_next) = count;
    }

    fn connections(&self) -> usize {
        lock(&self.state.connections).len()
    }

    fn connection(&self, index: usize) -> quinn::Connection {
        lock(&self.state.connections)[index].clone()
    }

    fn close_connections(&self) {
        for connection in lock(&self.state.connections).iter() {
            connection.close(0u32.into(), b"server-gone");
        }
    }

    fn refused(&self) -> Vec<Instant> {
        lock(&self.state.refused).clone()
    }

    fn version_refused(&self) -> Vec<Instant> {
        lock(&self.state.version_refused).clone()
    }

    fn streams(&self) -> Vec<StreamRecord> {
        lock(&self.state.streams).clone()
    }

    /// The streams whose records carry `kind`.
    fn streams_of(&self, kind: &str) -> Vec<StreamRecord> {
        self.streams()
            .into_iter()
            .filter(|stream| stream.kind() == Some(kind))
            .collect()
    }

    /// Every line received for `kind`, in stream order.
    fn lines(&self, kind: &str) -> Vec<String> {
        self.streams_of(kind)
            .iter()
            .flat_map(StreamRecord::lines)
            .collect()
    }

    /// Stops the latest stream carrying `kind`.
    fn stop_stream_of(&self, kind: &str) -> Result<()> {
        self.streams_of(kind)
            .last()
            .context("a stream carries the kind")?
            .stop
            .cancel();
        Ok(())
    }
}

impl Drop for Giganto {
    fn drop(&mut self) {
        self.task.abort();
        self.endpoint.close(0u32.into(), b"stopped");
    }
}

async fn accept(endpoint: Endpoint, state: Arc<GigantoState>) {
    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(serve(incoming, state.clone()));
    }
}

async fn serve(incoming: quinn::Incoming, state: Arc<GigantoState>) {
    let Ok(connection) = incoming.await else {
        lock(&state.refused).push(Instant::now());
        return;
    };
    let version_req = lock(&state.version_req).clone();
    let handshake = server_handshake(&connection, &version_req).await;
    if handshake.is_err() {
        lock(&state.version_refused).push(Instant::now());
        // Lets the refusal reach the client before the connection closes.
        sleep(Duration::from_millis(100)).await;
        return;
    }
    let index = {
        let mut connections = lock(&state.connections);
        connections.push(connection.clone());
        connections.len() - 1
    };
    while let Ok((send, recv)) = connection.accept_bi().await {
        tokio::spawn(read_stream(state.clone(), index, send, recv));
    }
}

async fn read_stream(
    state: Arc<GigantoState>,
    connection: usize,
    send: SendStream,
    mut recv: RecvStream,
) {
    let mut header = [0_u8; 4];
    if receive_record_header(&mut recv, &mut header).await.is_err() {
        return;
    }
    let stop = CancellationToken::new();
    let send = Arc::new(tokio::sync::Mutex::new(send));
    let index = {
        let mut streams = lock(&state.streams);
        let mut senders = lock(&state.senders);
        streams.push(StreamRecord {
            connection,
            header: u32::from_le_bytes(header),
            accepted_at: Instant::now(),
            records: Vec::new(),
            timestamps: Vec::new(),
            close_marker: false,
            ended: None,
            stop: stop.clone(),
        });
        senders.push(Some(send.clone()));
        streams.len() - 1
    };
    {
        let mut stop_next = lock(&state.stop_next);
        if *stop_next > 0 {
            *stop_next -= 1;
            stop.cancel();
        }
    }

    let end = loop {
        let kind = lock(&state.streams)[index].kind().map(str::to_string);
        let mut paused = state.paused.subscribe();
        let mut buf = Vec::new();
        let read = tokio::select! {
            read = async {
                let _ = paused
                    .wait_for(|paused| !kind.as_ref().is_some_and(|kind| paused.contains(kind)))
                    .await;
                recv_raw(&mut recv, &mut buf).await
            } => read,
            () = stop.cancelled() => {
                let _ = recv.stop(VarInt::from_u32(0));
                break "stopped".to_string();
            }
        };
        if let Err(error) = read {
            break format!("{error:?}");
        }
        let Ok(batch) = bincode::deserialize::<Vec<(i64, Vec<u8>)>>(&buf) else {
            break "malformed batch".to_string();
        };
        for (timestamp, data) in batch {
            if timestamp == CHANNEL_CLOSE_TIMESTAMP {
                let kind = {
                    let mut streams = lock(&state.streams);
                    streams[index].close_marker = true;
                    streams[index].kind().map(str::to_string)
                };
                let mut withhold = state.withhold.subscribe();
                let _ = withhold
                    .wait_for(|withhold| !withhold.holds(kind.as_deref()))
                    .await;
            } else if let Ok(log) = bincode::deserialize::<Log>(&data) {
                let withheld = lock(&state.withhold_acks).contains(&log.kind);
                let line = String::from_utf8_lossy(&log.log).into_owned();
                {
                    let mut pause_after = lock(&state.pause_after);
                    if pause_after
                        .as_ref()
                        .is_some_and(|(kind, after)| *kind == log.kind && *after == line)
                    {
                        *pause_after = None;
                        state.paused.send_modify(|paused| {
                            paused.insert(log.kind.clone());
                        });
                    }
                }
                {
                    let mut streams = lock(&state.streams);
                    streams[index].timestamps.push(timestamp);
                    streams[index].records.push((log.kind.clone(), line));
                }
                if withheld {
                    continue;
                }
                // Held under the lock, so a release sends every older ACK
                // first.
                let mut hold = state.hold.lock().await;
                if hold.kinds.contains(&log.kind) {
                    hold.acks.push((index, timestamp));
                    continue;
                }
                let _ = send.lock().await.write_all(&timestamp.to_be_bytes()).await;
                continue;
            }
            let _ = send.lock().await.write_all(&timestamp.to_be_bytes()).await;
        }
    };
    lock(&state.streams)[index].ended = Some(end);
    // Dropping the send side finishes the stream.
    lock(&state.senders)[index] = None;
}

/// The log files of a test.
struct LogFiles {
    dir: TempDir,
}

impl LogFiles {
    fn new() -> Result<Self> {
        let dir = tempfile::tempdir()?;
        std::fs::create_dir(dir.path().join("state"))?;
        Ok(Self { dir })
    }

    /// The state directory of the test's runtime.
    fn state(&self) -> PathBuf {
        self.path("state")
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// Creates the file `name` holding `lines`.
    fn create(&self, name: &str, lines: &[&str]) -> Result<PathBuf> {
        let path = self.path(name);
        std::fs::write(
            &path,
            lines
                .iter()
                .map(|line| format!("{line}\n"))
                .collect::<Vec<_>>()
                .concat(),
        )?;
        Ok(path)
    }
}

fn append(path: &Path, line: &str) -> Result<()> {
    use std::io::Write;

    let mut file = std::fs::OpenOptions::new().append(true).open(path)?;
    writeln!(file, "{line}")?;
    Ok(())
}

fn config(addr: SocketAddr, collectors: &[(&str, &Path)]) -> RemoteConfig {
    config_start(addr, collectors, StartPosition::Beginning)
}

fn config_start(
    addr: SocketAddr,
    collectors: &[(&str, &Path)],
    start: StartPosition,
) -> RemoteConfig {
    RemoteConfig {
        giganto_ingest_srv_addr: addr,
        giganto_name: SERVER_NAME.to_string(),
        collectors: collectors
            .iter()
            .map(|(kind, path)| CollectorConfig {
                collector_type: CollectorType::Log,
                kind: (*kind).to_string(),
                path: path.to_path_buf(),
                start,
            })
            .collect(),
    }
}

fn runtime(files: &TlsFiles, reload: &ReloadSignal, state_dir: &Path) -> CollectorRuntime {
    CollectorRuntime::new(files.clone(), reload.clone(), state_dir.to_path_buf())
        .with_retry_interval(RETRY)
}

/// Waits until `condition` holds, at most `within`.
async fn wait_for(what: &str, within: Duration, condition: impl Fn() -> bool) {
    let deadline = Instant::now() + within;
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting until {what}");
        sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_for_lines(giganto: &Giganto, kind: &str, lines: &[&str]) {
    wait_for(&format!("{kind} receives {lines:?}"), WAIT, || {
        let received = giganto.lines(kind);
        lines.iter().all(|line| received.iter().any(|r| r == line))
    })
    .await;
}

fn log_header() -> u32 {
    u32::from(RawEventKind::Log)
}

/// The checkpoint file of `kind` in `state_dir`.
fn checkpoint_file(state_dir: &Path, kind: &str) -> PathBuf {
    state_dir
        .join("checkpoints")
        .join("log")
        .join(format!("{kind}.json"))
}

/// The checkpoint of `kind`, if it can be read.
fn checkpoint(state_dir: &Path, kind: &str) -> Option<serde_json::Value> {
    let bytes = std::fs::read(checkpoint_file(state_dir, kind)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// The checkpoint of `kind` for `path` at `offset` in its current file.
#[cfg(unix)]
fn record(kind: &str, path: &Path, offset: u64) -> serde_json::Value {
    use std::os::unix::fs::MetadataExt;

    let metadata = std::fs::metadata(path).expect("the file exists");
    serde_json::json!({
        "type": "log",
        "kind": kind,
        "path": path.to_str().expect("a UTF-8 path"),
        "dev": metadata.dev(),
        "ino": metadata.ino(),
        "offset": offset,
    })
}

fn length(path: &Path) -> u64 {
    std::fs::metadata(path).expect("the file exists").len()
}

/// Waits until the checkpoint of `kind` is `expected`, at most `within`.
async fn wait_for_checkpoint(
    state_dir: &Path,
    kind: &str,
    expected: &serde_json::Value,
    within: Duration,
) {
    let deadline = Instant::now() + within;
    loop {
        let found = checkpoint(state_dir, kind);
        if found.as_ref() == Some(expected) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for the checkpoint of {kind} to be {expected}, found {found:?}"
        );
        sleep(Duration::from_millis(20)).await;
    }
}

/// The stop lines logged for `kind`.
fn stop_lines(text: &str, kind: &str) -> Vec<String> {
    let prefix = format!("Stopped collector {kind} for ");
    text.lines()
        .filter(|line| line.contains(&prefix))
        .map(str::to_string)
        .collect()
}

/// A PKI, a Giganto server trusting it, and client files issued by it.
fn setup() -> Result<(Pki, Giganto, Files)> {
    let pki = Pki::new()?;
    let giganto = Giganto::start(&pki)?;
    let files = Files::new(&pki, &pki.client()?)?;
    Ok((pki, giganto, files))
}

#[tokio::test]
async fn two_collectors_share_one_connection() -> Result<()> {
    let (_pki, giganto, files) = setup()?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1", "a2"])?;
    let b = logs.create("b.log", &["b1"])?;
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload, &logs.state());

    runtime
        .apply(config(giganto.addr, &[("kind_a", &a), ("kind_b", &b)]))
        .await;
    wait_for_lines(&giganto, "kind_a", &["a1", "a2"]).await;
    wait_for_lines(&giganto, "kind_b", &["b1"]).await;

    assert_eq!(giganto.connections(), 1);
    let streams = giganto.streams();
    assert_eq!(streams.len(), 2, "one stream per collector");
    for stream in &streams {
        assert_eq!(stream.header, log_header());
        assert_eq!(stream.connection, 0);
        let kinds = stream
            .records
            .iter()
            .map(|(kind, _)| kind.as_str())
            .collect::<HashSet<_>>();
        assert_eq!(kinds.len(), 1, "a stream carries one collector");
    }
    assert_eq!(giganto.lines("kind_a"), ["a1", "a2"]);
    assert_eq!(giganto.lines("kind_b"), ["b1"]);

    runtime.shutdown().await;
    let streams = giganto.streams();
    assert!(streams.iter().all(|stream| stream.close_marker));
    Ok(())
}

#[tokio::test]
async fn sixty_four_collectors_share_one_connection() -> Result<()> {
    let (_pki, giganto, files) = setup()?;
    let logs = LogFiles::new()?;
    let mut collectors = Vec::new();
    for index in 0..64 {
        let kind = format!("kind_{index:02}");
        let path = logs.create(&format!("{kind}.log"), &[&format!("line-{index}")])?;
        collectors.push((kind, path));
    }
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload, &logs.state());

    let entries = collectors
        .iter()
        .map(|(kind, path)| (kind.as_str(), path.as_path()))
        .collect::<Vec<_>>();
    runtime.apply(config(giganto.addr, &entries)).await;
    wait_for("every collector sends its line", WAIT, || {
        let streams = giganto.streams();
        collectors.iter().enumerate().all(|(index, (kind, _))| {
            streams.iter().any(|stream| {
                stream.kind() == Some(kind) && stream.lines() == [format!("line-{index}")]
            })
        })
    })
    .await;

    assert_eq!(giganto.connections(), 1);
    let streams = giganto.streams();
    assert_eq!(streams.len(), 64, "one stream per collector");
    let kinds = streams
        .iter()
        .filter_map(StreamRecord::kind)
        .collect::<HashSet<_>>();
    assert_eq!(kinds.len(), 64);
    assert!(streams.iter().all(|stream| stream.header == log_header()));

    runtime.shutdown().await;
    assert!(giganto.streams().iter().all(|stream| stream.close_marker));
    Ok(())
}

#[tokio::test]
async fn applies_add_and_remove_collectors() -> Result<()> {
    let (logs_capture, _guard) = Logs::capture();
    let (_pki, giganto, files) = setup()?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1"])?;
    let b = logs.create("b.log", &["b1"])?;
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload, &logs.state());

    runtime.apply(config(giganto.addr, &[("kind_a", &a)])).await;
    wait_for_lines(&giganto, "kind_a", &["a1"]).await;

    // Adding a collector opens one new stream.
    let both = config(giganto.addr, &[("kind_a", &a), ("kind_b", &b)]);
    runtime.apply(both.clone()).await;
    wait_for_lines(&giganto, "kind_b", &["b1"]).await;
    sleep(SETTLE).await;
    let streams = giganto.streams();
    assert_eq!(streams.len(), 2);
    let kept = &giganto.streams_of("kind_a")[0];
    assert!(kept.ended.is_none() && !kept.close_marker, "{kept:?}");
    assert!(
        logs_capture
            .text()
            .contains("Applied a configuration with 2 collectors: 1 started, 0 stopped")
    );

    // An equal configuration changes nothing.
    let applied = logs_capture
        .text()
        .matches("Applied a configuration")
        .count();
    runtime.apply(both).await;
    sleep(SETTLE).await;
    assert_eq!(giganto.streams().len(), 2);
    assert_eq!(
        logs_capture
            .text()
            .matches("Applied a configuration")
            .count(),
        applied
    );

    // Removing a collector closes its stream with its close marker, and the
    // apply returns after its close ACK.
    let started = Instant::now();
    runtime.apply(config(giganto.addr, &[("kind_a", &a)])).await;
    assert!(started.elapsed() < Duration::from_secs(5));
    let removed = &giganto.streams_of("kind_b")[0];
    assert!(removed.close_marker, "{removed:?}");
    let text = logs_capture.text();
    assert!(text.contains(&format!(
        "Stopped collector kind_b for {} with close ACK Received",
        b.display()
    )));
    assert!(text.contains("Applied a configuration with 1 collectors: 0 started, 1 stopped"));
    let kept = &giganto.streams_of("kind_a")[0];
    assert!(kept.ended.is_none() && !kept.close_marker, "{kept:?}");
    assert_eq!(giganto.streams().len(), 2);

    append(&a, "a2")?;
    wait_for_lines(&giganto, "kind_a", &["a2"]).await;
    assert_eq!(giganto.streams().len(), 2, "the kept stream keeps sending");
    assert_eq!(giganto.connections(), 1);

    runtime.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn address_change_from_a_silent_port_takes_effect() -> Result<()> {
    let (_pki, giganto, files) = setup()?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1"])?;
    let silent = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload, &logs.state());

    let started = Instant::now();
    runtime
        .apply(config(silent.local_addr()?, &[("kind_a", &a)]))
        .await;
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "the apply does not wait for the connection"
    );
    sleep(SETTLE).await;
    assert_eq!(giganto.connections(), 0);

    let started = Instant::now();
    runtime.apply(config(giganto.addr, &[("kind_a", &a)])).await;
    assert!(started.elapsed() < Duration::from_secs(1));
    wait_for_lines(&giganto, "kind_a", &["a1"]).await;
    assert_eq!(giganto.connections(), 1);

    runtime.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn address_change_moves_kept_streams_to_the_new_connection() -> Result<()> {
    let (logs_capture, _guard) = Logs::capture();
    let pki = Pki::new()?;
    let first = Giganto::start(&pki)?;
    let second = Giganto::start(&pki)?;
    let files = Files::new(&pki, &pki.client()?)?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1"])?;
    let b = logs.create("b.log", &["b1"])?;
    let c = logs.create("c.log", &["c1"])?;
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload, &logs.state());

    runtime
        .apply(config(first.addr, &[("kind_a", &a), ("kind_b", &b)]))
        .await;
    wait_for_lines(&first, "kind_a", &["a1"]).await;
    wait_for_lines(&first, "kind_b", &["b1"]).await;

    let started = Instant::now();
    runtime
        .apply(config(second.addr, &[("kind_a", &a), ("kind_c", &c)]))
        .await;
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(logs_capture.text().contains(&format!(
        "Stopped collector kind_b for {} without a close marker",
        b.display()
    )));
    sleep(SETTLE).await;
    let lines = stop_lines(&logs_capture.text(), "kind_b");
    assert_eq!(lines.len(), 1, "{lines:?}");
    wait_for_lines(&second, "kind_c", &["c1"]).await;
    let old = first.connection(0);
    wait_for("the old connection is closed", WAIT, || {
        old.close_reason().is_some()
    })
    .await;

    append(&a, "a2")?;
    wait_for_lines(&second, "kind_a", &["a2"]).await;
    assert_eq!(second.connections(), 1);
    assert_eq!(first.connections(), 1);
    assert!(!first.lines("kind_a").contains(&"a2".to_string()));
    assert!(first.streams().iter().all(|stream| !stream.close_marker));

    runtime.shutdown().await;
    assert!(second.streams().iter().all(|stream| stream.close_marker));
    Ok(())
}

#[tokio::test]
async fn tls_refusal_before_the_first_connect_ends_with_new_files() -> Result<()> {
    let (logs_capture, _guard) = Logs::capture();
    let pki = Pki::new()?;
    let untrusted = Pki::new()?;
    let giganto = Giganto::start(&pki)?;
    // The CA file verifies the server; the identity is from a CA the server
    // does not trust.
    let files = Files::new(&pki, &untrusted.client()?)?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1"])?;
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload, &logs.state());

    runtime.apply(config(giganto.addr, &[("kind_a", &a)])).await;
    wait_for("connects are refused and retried", WAIT, || {
        giganto.refused().len() >= 3
    })
    .await;
    assert_eq!(giganto.connections(), 0);
    let text = logs_capture.text();
    assert!(
        text.lines()
            .any(|line| line.contains("WARN") && line.contains("Cannot connect to Giganto")),
        "{text}"
    );
    assert!(!text.contains("ERROR"), "{text}");

    files.write_identity(&pki.client()?)?;
    wait_for_lines(&giganto, "kind_a", &["a1"]).await;
    assert_eq!(giganto.connections(), 1);

    runtime.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn tls_refusal_on_reconnects_ends_after_reload() -> Result<()> {
    let pki = Pki::new()?;
    let other = Pki::new()?;
    let giganto = Giganto::start(&pki)?;
    let files = Files::new(&pki, &pki.client()?)?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1"])?;
    let b = logs.create("b.log", &["b1"])?;
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload, &logs.state());

    runtime
        .apply(config(giganto.addr, &[("kind_a", &a), ("kind_b", &b)]))
        .await;
    wait_for_lines(&giganto, "kind_a", &["a1"]).await;
    wait_for_lines(&giganto, "kind_b", &["b1"]).await;

    // The server now trusts only the other CA and drops the connection.
    giganto.trust(&pki.server, &other.ca)?;
    giganto.close_connections();
    append(&a, "a2")?;
    append(&b, "b2")?;
    wait_for("reconnects are refused", WAIT, || {
        giganto.refused().len() >= 2
    })
    .await;

    // New files alone are not read by an established connection's reconnects.
    files.write_identity(&other.client()?)?;
    let refused = giganto.refused().len();
    wait_for("reconnects keep being refused", WAIT, || {
        giganto.refused().len() >= refused + 2
    })
    .await;
    assert_eq!(giganto.connections(), 1);

    reload.request();
    wait_for_lines(&giganto, "kind_a", &["a2"]).await;
    wait_for_lines(&giganto, "kind_b", &["b2"]).await;
    assert_eq!(giganto.connections(), 2);
    for kind in ["kind_a", "kind_b"] {
        let streams = giganto.streams_of(kind);
        let last = streams.last().context("a stream")?;
        assert_eq!(last.connection, 1, "the stream moves to the new connection");
        assert_eq!(last.header, log_header());
    }

    runtime.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn version_refusal_is_retried() -> Result<()> {
    let (logs_capture, _guard) = Logs::capture();
    let (_pki, giganto, files) = setup()?;
    giganto.set_version_req(">=99.0.0");
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1"])?;
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload, &logs.state());

    // Before the first connection.
    runtime.apply(config(giganto.addr, &[("kind_a", &a)])).await;
    wait_for("handshakes are refused and retried", WAIT, || {
        giganto.version_refused().len() >= 3
    })
    .await;
    let text = logs_capture.text();
    assert!(
        text.lines()
            .any(|line| line.contains("WARN") && line.contains("Giganto handshake failed")),
        "{text}"
    );
    giganto.set_version_req(GIGANTO_VERSION_REQ);
    wait_for_lines(&giganto, "kind_a", &["a1"]).await;
    assert_eq!(giganto.connections(), 1);

    // On an established connection's reconnects, which the owner spaces by
    // its reconnect delay.
    giganto.set_version_req(">=99.0.0");
    giganto.close_connections();
    append(&a, "a2")?;
    let refused = giganto.version_refused().len();
    wait_for("reconnect handshakes are refused", WAIT, || {
        giganto.version_refused().len() >= refused + 2
    })
    .await;
    let times = giganto.version_refused();
    let spacing = times[refused + 1] - times[refused];
    assert!(spacing >= Duration::from_millis(1900), "{spacing:?}");

    giganto.set_version_req(GIGANTO_VERSION_REQ);
    wait_for_lines(&giganto, "kind_a", &["a2"]).await;
    assert_eq!(giganto.connections(), 2);
    assert!(!logs_capture.text().contains("ERROR"));

    runtime.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn lost_connection_is_replaced_once_for_every_stream() -> Result<()> {
    let (logs_capture, _guard) = Logs::capture();
    let (_pki, giganto, files) = setup()?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1"])?;
    let b = logs.create("b.log", &["b1"])?;
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload, &logs.state());

    runtime
        .apply(config(giganto.addr, &[("kind_a", &a), ("kind_b", &b)]))
        .await;
    wait_for_lines(&giganto, "kind_a", &["a1"]).await;
    wait_for_lines(&giganto, "kind_b", &["b1"]).await;

    giganto.close_connections();
    sleep(SETTLE).await;
    assert_eq!(
        giganto.connections(),
        1,
        "a collector notices the loss only when it next sends"
    );
    append(&a, "a2")?;
    append(&b, "b2")?;
    wait_for_lines(&giganto, "kind_a", &["a2"]).await;
    wait_for_lines(&giganto, "kind_b", &["b2"]).await;
    sleep(SETTLE).await;

    assert_eq!(giganto.connections(), 2, "exactly one new connection");
    for kind in ["kind_a", "kind_b"] {
        let streams = giganto.streams_of(kind);
        assert_eq!(streams.len(), 2, "{kind}: {streams:?}");
        assert_eq!(streams[1].connection, 1);
        assert_eq!(streams[1].header, log_header());
    }

    let text = logs_capture.text();
    for kind in ["kind_a", "kind_b"] {
        let failure = format!("Sending failed for {kind}:");
        let failures = text
            .lines()
            .filter(|line| line.contains("WARN") && line.contains(&failure))
            .count();
        assert_eq!(failures, 1, "{text}");
        assert!(
            text.contains(&format!("Sending again for {kind}")),
            "{text}"
        );
    }

    runtime.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn stopped_stream_is_reopened_alone_and_spaced() -> Result<()> {
    let (_pki, giganto, files) = setup()?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1"])?;
    let b = logs.create("b.log", &["b1"])?;
    let reload = ReloadSignal::new();
    let retry = Duration::from_secs(1);
    let mut runtime = CollectorRuntime::new(files.files.clone(), reload.clone(), logs.state())
        .with_retry_interval(retry);

    runtime
        .apply(config(giganto.addr, &[("kind_a", &a), ("kind_b", &b)]))
        .await;
    wait_for_lines(&giganto, "kind_a", &["a1"]).await;
    wait_for_lines(&giganto, "kind_b", &["b1"]).await;

    // Stopping one stream reopens only that stream.
    giganto.stop_stream_of("kind_a")?;
    append(&a, "a2")?;
    wait_for_lines(&giganto, "kind_a", &["a2"]).await;
    assert_eq!(giganto.streams().len(), 3);
    assert_eq!(giganto.streams_of("kind_a").len(), 2);
    let untouched = &giganto.streams_of("kind_b")[0];
    assert!(untouched.ended.is_none() && !untouched.close_marker);
    assert_eq!(giganto.connections(), 1);

    // A stream stopped again right after its reopen is reopened only after
    // the retry interval.
    let writer_stop = CancellationToken::new();
    let writer = {
        let a = a.clone();
        let stop = writer_stop.clone();
        tokio::spawn(async move {
            let mut count = 0;
            while !stop.is_cancelled() {
                count += 1;
                let _ = append(&a, &format!("w{count}"));
                sleep(Duration::from_millis(50)).await;
            }
        })
    };
    giganto.stop_next_streams(1);
    giganto.stop_stream_of("kind_a")?;
    wait_for("two more streams are opened", WAIT, || {
        giganto.streams().len() >= 5
    })
    .await;
    writer_stop.cancel();
    writer.await?;
    let streams = giganto.streams();
    let spacing = streams[4].accepted_at - streams[3].accepted_at;
    assert!(spacing >= Duration::from_millis(800), "{spacing:?}");
    let untouched = &giganto.streams_of("kind_b")[0];
    assert!(untouched.ended.is_none() && !untouched.close_marker);
    assert_eq!(giganto.connections(), 1);

    runtime.shutdown().await;
    Ok(())
}

#[cfg(unix)]
fn mkfifo(path: &Path) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;

    let path = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    // SAFETY: `path` is a valid NUL-terminated string.
    let result = unsafe { libc::mkfifo(path.as_ptr(), 0o644) };
    anyhow::ensure!(result == 0, "mkfifo failed");
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn missing_and_unusable_paths_do_not_stop_others() -> Result<()> {
    let (logs_capture, _guard) = Logs::capture();
    let (_pki, giganto, files) = setup()?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1"])?;
    let missing = logs.path("missing.log");
    let fifo = logs.path("fifo.log");
    mkfifo(&fifo)?;
    let dir = logs.path("dir.log");
    std::fs::create_dir(&dir)?;
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload, &logs.state());

    runtime
        .apply(config(
            giganto.addr,
            &[
                ("kind_a", &a),
                ("kind_m", &missing),
                ("kind_f", &fifo),
                ("kind_d", &dir),
            ],
        ))
        .await;
    wait_for_lines(&giganto, "kind_a", &["a1"]).await;
    // More than two retries of every 3 s.
    sleep(Duration::from_secs(7)).await;

    let text = logs_capture.text();
    let warnings = |path: &Path, reason: &str| {
        text.lines()
            .filter(|line| {
                line.contains("WARN")
                    && line.contains(&path.display().to_string())
                    && line.contains(reason)
            })
            .count()
    };
    assert_eq!(warnings(&missing, "the path does not exist"), 1, "{text}");
    assert_eq!(
        warnings(&fifo, "the path is not a regular file"),
        1,
        "{text}"
    );
    assert_eq!(
        warnings(&dir, "the path is not a regular file"),
        1,
        "{text}"
    );

    append(&a, "a2")?;
    wait_for_lines(&giganto, "kind_a", &["a2"]).await;
    std::fs::write(&missing, "m1\nm2\n")?;
    wait_for_lines(&giganto, "kind_m", &["m1", "m2"]).await;
    assert_eq!(giganto.lines("kind_m"), ["m1", "m2"]);
    assert!(
        logs_capture
            .text()
            .contains(&format!("Reading {} for kind_m", missing.display()))
    );

    let started = Instant::now();
    runtime.shutdown().await;
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(giganto.streams().iter().all(|stream| stream.close_marker));
    assert!(!logs_capture.text().contains("ERROR"));
    Ok(())
}

#[tokio::test]
async fn removal_without_a_close_ack_returns_by_the_deadline() -> Result<()> {
    let (logs_capture, _guard) = Logs::capture();
    let (_pki, giganto, files) = setup()?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1"])?;
    let b = logs.create("b.log", &["b1"])?;
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload, &logs.state());

    runtime
        .apply(config(giganto.addr, &[("kind_a", &a), ("kind_b", &b)]))
        .await;
    wait_for_lines(&giganto, "kind_a", &["a1"]).await;
    wait_for_lines(&giganto, "kind_b", &["b1"]).await;

    giganto.withhold(Withhold::All);
    let started = Instant::now();
    runtime.apply(config(giganto.addr, &[("kind_a", &a)])).await;
    let elapsed = started.elapsed();
    assert!(elapsed >= CLOSE_DEADLINE, "{elapsed:?}");
    assert!(
        elapsed < CLOSE_DEADLINE + Duration::from_secs(2),
        "{elapsed:?}"
    );
    assert!(giganto.streams_of("kind_b")[0].close_marker);
    let kept = &giganto.streams_of("kind_a")[0];
    assert!(kept.ended.is_none() && !kept.close_marker);
    sleep(SETTLE).await;
    assert_one_deadline_stop_line(&logs_capture.text(), "kind_b", &b);

    giganto.withhold(Withhold::Nothing);
    runtime.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn shutdown_without_close_acks_returns_after_the_deadline() -> Result<()> {
    let (logs_capture, _guard) = Logs::capture();
    let (_pki, giganto, files) = setup()?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1"])?;
    let b = logs.create("b.log", &["b1"])?;
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload, &logs.state());

    runtime
        .apply(config(giganto.addr, &[("kind_a", &a), ("kind_b", &b)]))
        .await;
    wait_for_lines(&giganto, "kind_a", &["a1"]).await;
    wait_for_lines(&giganto, "kind_b", &["b1"]).await;

    giganto.withhold(Withhold::All);
    let started = Instant::now();
    runtime.shutdown().await;
    let elapsed = started.elapsed();
    assert!(elapsed >= CLOSE_DEADLINE, "{elapsed:?}");
    assert!(elapsed < Duration::from_secs(20), "{elapsed:?}");
    assert!(giganto.streams().iter().all(|stream| stream.close_marker));
    sleep(SETTLE).await;
    let text = logs_capture.text();
    assert_one_deadline_stop_line(&text, "kind_a", &a);
    assert_one_deadline_stop_line(&text, "kind_b", &b);
    Ok(())
}

/// Asserts that the collector of `kind` logged one stop line, for a close
/// cut off at the deadline.
///
/// The close's own 15 s wait for the close ACK ends within the same timer
/// tick as the deadline, so either side can log the line, never both.
fn assert_one_deadline_stop_line(text: &str, kind: &str, path: &Path) {
    let lines = stop_lines(text, kind);
    assert_eq!(lines.len(), 1, "{text}");
    let prefix = format!("Stopped collector {kind} for {} ", path.display());
    assert!(
        lines[0].contains(&format!(
            "{prefix}at the close deadline, without waiting further"
        )) || lines[0].contains(&format!("{prefix}with close ACK TimedOut")),
        "{}",
        lines[0]
    );
}

#[tokio::test]
async fn shutdown_after_a_dropped_apply_stops_every_collector() -> Result<()> {
    let (logs_capture, _guard) = Logs::capture();
    let (_pki, giganto, files) = setup()?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1"])?;
    let b = logs.create("b.log", &["b1"])?;
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload, &logs.state());

    runtime
        .apply(config(giganto.addr, &[("kind_a", &a), ("kind_b", &b)]))
        .await;
    wait_for_lines(&giganto, "kind_a", &["a1"]).await;
    wait_for_lines(&giganto, "kind_b", &["b1"]).await;

    // The apply is dropped while it waits for kind_b's close ACK.
    giganto.withhold(Withhold::Kinds(HashSet::from(["kind_b".to_string()])));
    let dropped = timeout(
        Duration::from_secs(1),
        runtime.apply(config(giganto.addr, &[("kind_a", &a)])),
    )
    .await;
    assert!(dropped.is_err(), "the apply waits for the close ACK");
    assert!(giganto.streams_of("kind_b")[0].close_marker);

    // kind_b's close ACK arrives a second into the shutdown, which waits for
    // it.
    let release = {
        let state = giganto.state.clone();
        tokio::spawn(async move {
            sleep(Duration::from_secs(1)).await;
            state.withhold.send_replace(Withhold::Nothing);
        })
    };
    let started = Instant::now();
    runtime.shutdown().await;
    let elapsed = started.elapsed();
    release.await?;
    assert!(elapsed >= Duration::from_millis(900), "{elapsed:?}");
    assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
    assert!(giganto.streams().iter().all(|stream| stream.close_marker));
    let text = logs_capture.text();
    for (kind, path) in [("kind_a", &a), ("kind_b", &b)] {
        assert!(
            text.contains(&format!(
                "Stopped collector {kind} for {} with close ACK Received",
                path.display()
            )),
            "{text}"
        );
    }
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn checkpoints_follow_the_acknowledged_lines() -> Result<()> {
    let (_pki, giganto, files) = setup()?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1"])?;
    let b = logs.create("b.log", &["b1", "", "b2"])?;
    let state = logs.state();
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload, &state);

    runtime
        .apply(config(giganto.addr, &[("kind_a", &a), ("kind_b", &b)]))
        .await;
    wait_for_lines(&giganto, "kind_a", &["a1"]).await;
    wait_for_lines(&giganto, "kind_b", &["b1", "b2"]).await;
    wait_for_checkpoint(&state, "kind_a", &record("kind_a", &a, length(&a)), WAIT).await;
    wait_for_checkpoint(&state, "kind_b", &record("kind_b", &b, length(&b)), WAIT).await;

    // While the readers wait at EOF, each acknowledged line reaches the
    // checkpoint within a second.
    append(&a, "a2")?;
    append(&b, "b3")?;
    wait_for_lines(&giganto, "kind_a", &["a2"]).await;
    wait_for_lines(&giganto, "kind_b", &["b3"]).await;
    let within = Duration::from_secs(1) + Duration::from_millis(500);
    wait_for_checkpoint(&state, "kind_a", &record("kind_a", &a, length(&a)), within).await;
    wait_for_checkpoint(&state, "kind_b", &record("kind_b", &b, length(&b)), within).await;

    // A clean stop saves everything written.
    append(&a, "a3")?;
    wait_for_lines(&giganto, "kind_a", &["a3"]).await;
    runtime.shutdown().await;
    assert_eq!(
        checkpoint(&state, "kind_a"),
        Some(record("kind_a", &a, length(&a)))
    );
    assert_eq!(
        checkpoint(&state, "kind_b"),
        Some(record("kind_b", &b, length(&b)))
    );
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn shutdown_without_acks_saves_the_last_acknowledged_line() -> Result<()> {
    let (_pki, giganto, files) = setup()?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1"])?;
    let b = logs.create("b.log", &["b1"])?;
    let state = logs.state();
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload, &state);

    runtime
        .apply(config(giganto.addr, &[("kind_a", &a), ("kind_b", &b)]))
        .await;
    wait_for_lines(&giganto, "kind_a", &["a1"]).await;
    let acknowledged = length(&a);
    wait_for_checkpoint(&state, "kind_a", &record("kind_a", &a, acknowledged), WAIT).await;

    // kind_a's later lines and its close are never acknowledged.
    giganto.withhold_acks(&["kind_a"]);
    giganto.withhold(Withhold::Kinds(HashSet::from(["kind_a".to_string()])));
    append(&a, "a2")?;
    append(&a, "a3")?;
    wait_for_lines(&giganto, "kind_a", &["a2", "a3"]).await;
    sleep(SETTLE).await;
    assert_eq!(
        checkpoint(&state, "kind_a"),
        Some(record("kind_a", &a, acknowledged))
    );

    let started = Instant::now();
    runtime.shutdown().await;
    assert!(started.elapsed() >= CLOSE_DEADLINE);
    assert_eq!(
        checkpoint(&state, "kind_a"),
        Some(record("kind_a", &a, acknowledged))
    );
    assert_eq!(
        checkpoint(&state, "kind_b"),
        Some(record("kind_b", &b, length(&b)))
    );
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn a_replaced_stream_keeps_the_acknowledged_position() -> Result<()> {
    let (_pki, giganto, files) = setup()?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1"])?;
    let state = logs.state();
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload, &state);

    runtime.apply(config(giganto.addr, &[("kind_a", &a)])).await;
    wait_for_lines(&giganto, "kind_a", &["a1"]).await;
    let acknowledged = length(&a);
    wait_for_checkpoint(&state, "kind_a", &record("kind_a", &a, acknowledged), WAIT).await;

    // a2 is never acknowledged, and its stream is stopped.
    giganto.withhold_acks(&["kind_a"]);
    append(&a, "a2")?;
    wait_for_lines(&giganto, "kind_a", &["a2"]).await;
    giganto.stop_stream_of("kind_a")?;
    append(&a, "a3")?;
    wait_for("a3 arrives on a new stream", WAIT, || {
        giganto
            .streams_of("kind_a")
            .get(1)
            .is_some_and(|stream| stream.lines().contains(&"a3".to_string()))
    })
    .await;
    // The unacknowledged a2 is sent again on the new stream, from the
    // acknowledged position.
    assert_eq!(giganto.streams_of("kind_a")[1].lines(), ["a2", "a3"]);

    // The position stays put while the reader idles.
    sleep(SETTLE).await;
    assert_eq!(
        checkpoint(&state, "kind_a"),
        Some(record("kind_a", &a, acknowledged))
    );

    // It moves on once a line sent on the new stream is acknowledged.
    giganto.withhold_acks(&[]);
    append(&a, "a4")?;
    wait_for_lines(&giganto, "kind_a", &["a4"]).await;
    wait_for_checkpoint(&state, "kind_a", &record("kind_a", &a, length(&a)), WAIT).await;

    runtime.shutdown().await;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn the_starting_position_is_saved_before_sending() -> Result<()> {
    let (logs_capture, _guard) = Logs::capture();
    let (_pki, giganto, files) = setup()?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1"])?;
    let state = logs.state();
    // A directory in the way of the temporary file makes every save fail.
    let obstacle = state
        .join("checkpoints")
        .join("log")
        .join("kind_a.json.tmp");
    std::fs::create_dir_all(&obstacle)?;
    giganto.withhold_acks(&["kind_a"]);
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload, &state);

    runtime.apply(config(giganto.addr, &[("kind_a", &a)])).await;
    // More than two retries of every 3 s.
    sleep(Duration::from_secs(7)).await;
    assert!(giganto.streams().is_empty(), "{:?}", giganto.streams());
    assert!(checkpoint(&state, "kind_a").is_none());
    let text = logs_capture.text();
    let warnings = text
        .lines()
        .filter(|line| {
            line.contains("WARN") && line.contains("Cannot save the checkpoint of kind_a")
        })
        .count();
    assert_eq!(warnings, 1, "{text}");

    std::fs::remove_dir(&obstacle)?;
    wait_for_lines(&giganto, "kind_a", &["a1"]).await;
    // Nothing is acknowledged, so the checkpoint is the starting position.
    assert_eq!(checkpoint(&state, "kind_a"), Some(record("kind_a", &a, 0)));
    assert!(
        logs_capture
            .text()
            .contains("Saved the checkpoint of kind_a again")
    );

    giganto.withhold_acks(&[]);
    runtime.shutdown().await;
    assert!(!logs_capture.text().contains("ERROR"));
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn a_corrupt_checkpoint_is_replaced_by_the_starting_position() -> Result<()> {
    let (logs_capture, _guard) = Logs::capture();
    let (_pki, giganto, files) = setup()?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1"])?;
    let state = logs.state();
    let file = checkpoint_file(&state, "kind_a");
    std::fs::create_dir_all(file.parent().context("a parent")?)?;
    std::fs::write(&file, b"{\"type\":\"log\",")?;
    giganto.withhold_acks(&["kind_a"]);
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload, &state);

    runtime.apply(config(giganto.addr, &[("kind_a", &a)])).await;
    // The starting position is the end of the file.
    wait_for_checkpoint(&state, "kind_a", &record("kind_a", &a, length(&a)), WAIT).await;
    append(&a, "a2")?;
    wait_for_lines(&giganto, "kind_a", &["a2"]).await;
    assert_eq!(giganto.lines("kind_a"), ["a2"], "a1 is not sent");
    let text = logs_capture.text();
    let expected = format!(
        "Checkpoint {} is unusable: not valid JSON; using the end of {} instead",
        file.display(),
        a.display()
    );
    assert!(
        text.lines()
            .any(|line| line.contains("WARN") && line.contains(&expected)),
        "{text}"
    );

    giganto.withhold_acks(&[]);
    runtime.shutdown().await;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn applies_delete_and_replace_checkpoints() -> Result<()> {
    let (logs_capture, _guard) = Logs::capture();
    let (_pki, giganto, files) = setup()?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1"])?;
    let moved = logs.create("moved.log", &["m1", "m2"])?;
    let b = logs.create("b.log", &["b1"])?;
    let state = logs.state();
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload, &state);

    runtime
        .apply(config(giganto.addr, &[("kind_a", &a), ("kind_b", &b)]))
        .await;
    wait_for_lines(&giganto, "kind_a", &["a1"]).await;
    wait_for_lines(&giganto, "kind_b", &["b1"]).await;
    wait_for_checkpoint(&state, "kind_a", &record("kind_a", &a, length(&a)), WAIT).await;
    wait_for_checkpoint(&state, "kind_b", &record("kind_b", &b, length(&b)), WAIT).await;
    let journal = state.join("checkpoints").join("journal.json");
    std::fs::write(&journal, b"{}\n")?;
    let stray = state
        .join("checkpoints")
        .join("log")
        .join("kind_b.json.tmp");
    std::fs::write(&stray, b"{")?;
    // kind_b has a line in flight as it is removed.
    append(&b, "b2")?;

    runtime
        .apply(config(giganto.addr, &[("kind_a", &moved)]))
        .await;
    assert!(!checkpoint_file(&state, "kind_b").exists());
    assert!(!stray.exists());
    assert!(journal.exists());
    assert!(
        logs_capture
            .text()
            .contains("Deleted the checkpoint of kind_b")
    );
    wait_for_checkpoint(
        &state,
        "kind_a",
        &record("kind_a", &moved, length(&moved)),
        WAIT,
    )
    .await;
    assert!(logs_capture.text().contains(&format!(
        "Checkpoint {} is for {}, not {}; it will be replaced",
        checkpoint_file(&state, "kind_a").display(),
        a.display(),
        moved.display()
    )));

    // Nothing of a removed collector lands afterwards.
    sleep(SETTLE).await;
    assert!(!checkpoint_file(&state, "kind_b").exists());
    assert_eq!(
        checkpoint(&state, "kind_a"),
        Some(record("kind_a", &moved, length(&moved)))
    );

    runtime.shutdown().await;
    assert!(!checkpoint_file(&state, "kind_b").exists());
    Ok(())
}

/// Runs the binary in remote mode against the mock manager, serving two
/// collectors that send to the in-process Giganto server, and checks that
/// `SIGTERM` closes both streams with their close markers and exits 0.
#[cfg(unix)]
#[tokio::test]
async fn binary_closes_streams_on_sigterm() -> Result<()> {
    use std::io::BufRead;

    let (pki, giganto, files) = setup()?;
    let mock = support::Mock::start(&pki)?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1"])?;
    let b = logs.create("b.log", &["b1"])?;
    mock.set_config(Some(&format!(
        r#"
giganto_ingest_srv_addr = "{}"
giganto_name = "{SERVER_NAME}"

[[collectors]]
type = "log"
kind = "kind_a"
path = "{}"
start = "beginning"

[[collectors]]
type = "log"
kind = "kind_b"
path = "{}"
start = "beginning"
"#,
        giganto.addr,
        a.display(),
        b.display()
    )));
    let state_dir = tempfile::tempdir()?;
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_reproduce"))
        .arg("--cert")
        .arg(&files.files.cert)
        .arg("--key")
        .arg(&files.files.key)
        .arg("--ca-certs")
        .arg(&files.files.ca_certs[0])
        .arg("--state-dir")
        .arg(state_dir.path())
        .arg(format!("{SERVER_NAME}@{}", mock.addr))
        .env_remove("RUST_LOG")
        .env_remove("JOURNAL_STREAM")
        .stdout(std::process::Stdio::piped())
        .spawn()?;
    let stdout = Arc::new(Mutex::new(String::new()));
    let reader = child.stdout.take().context("piped stdout")?;
    let output = stdout.clone();
    std::thread::spawn(move || {
        for line in std::io::BufReader::new(reader)
            .lines()
            .map_while(Result::ok)
        {
            let mut output = output.lock().expect("lock");
            output.push_str(&line);
            output.push('\n');
        }
    });
    let output = || stdout.lock().expect("lock").clone();

    let result = async {
        wait_for_lines(&giganto, "kind_a", &["a1"]).await;
        wait_for_lines(&giganto, "kind_b", &["b1"]).await;
        assert_eq!(giganto.streams().len(), 2);
        assert_eq!(giganto.connections(), 1);

        support::send_signal(&child, libc::SIGTERM);
        let deadline = Instant::now() + CLOSE_DEADLINE;
        loop {
            if let Some(status) = child.try_wait()? {
                break Ok::<_, anyhow::Error>(status);
            }
            anyhow::ensure!(Instant::now() < deadline, "no exit within 15 s of SIGTERM");
            sleep(Duration::from_millis(20)).await;
        }
    }
    .await;
    let status = match result {
        Ok(status) => status,
        Err(error) => {
            let _ = child.kill();
            panic!("{error:#}; output:\n{}", output());
        }
    };
    assert_eq!(status.code(), Some(0), "{}", output());
    assert!(
        giganto.streams().iter().all(|stream| stream.close_marker),
        "{:?}\n{}",
        giganto.streams(),
        output()
    );
    for (kind, path) in [("kind_a", &a), ("kind_b", &b)] {
        assert_eq!(
            checkpoint(state_dir.path(), kind),
            Some(record(kind, path, length(path))),
            "{}",
            output()
        );
    }
    Ok(())
}

/// Copies `path` aside and truncates it, as a copy-truncate rotation does,
/// then writes `lines` to it.
fn copy_truncate(path: &Path, lines: &[&str]) -> Result<()> {
    let mut copy = path.as_os_str().to_owned();
    copy.push(".1");
    std::fs::copy(path, &copy)?;
    std::fs::OpenOptions::new()
        .write(true)
        .open(path)?
        .set_len(0)?;
    for line in lines {
        append(path, line)?;
    }
    Ok(())
}

/// Tells whether this process has `path` open.
#[cfg(unix)]
fn is_open(path: &Path) -> bool {
    let path = std::fs::canonicalize(path).expect("the file exists");
    open_paths().contains(&path)
}

/// The files this process has open.
#[cfg(target_os = "linux")]
fn open_paths() -> Vec<PathBuf> {
    std::fs::read_dir("/proc/self/fd")
        .expect("/proc/self/fd")
        .flatten()
        .filter_map(|entry| std::fs::read_link(entry.path()).ok())
        .collect()
}

/// The files this process has open.
#[cfg(all(unix, not(target_os = "linux")))]
fn open_paths() -> Vec<PathBuf> {
    use std::os::unix::ffi::OsStrExt;

    let mut paths = Vec::new();
    for fd in 0..4096 {
        let mut buf = [0_u8; libc::PATH_MAX as usize];
        // SAFETY: `buf` holds `PATH_MAX` bytes, as `F_GETPATH` requires.
        if unsafe { libc::fcntl(fd, libc::F_GETPATH, buf.as_mut_ptr()) } == 0 {
            let len = buf.iter().position(|&byte| byte == 0).unwrap_or(buf.len());
            paths.push(PathBuf::from(std::ffi::OsStr::from_bytes(&buf[..len])));
        }
    }
    paths
}

/// The lines `kind` received on its streams from the `from`th on.
fn lines_from(giganto: &Giganto, kind: &str, from: usize) -> Vec<String> {
    giganto
        .streams_of(kind)
        .iter()
        .skip(from)
        .flat_map(StreamRecord::lines)
        .collect()
}

/// Waits until the log holds `text`.
async fn wait_for_log(logs: &Logs, text: &str) {
    wait_for(&format!("the log holds {text:?}"), WAIT, || {
        logs.text().contains(text)
    })
    .await;
}

#[cfg(unix)]
#[tokio::test]
async fn start_end_skips_existing_lines_and_a_crash_sends_the_unacknowledged_ones_again()
-> Result<()> {
    let (_pki, giganto, files) = setup()?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1", "a2"])?;
    let state = logs.state();
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload, &state);

    runtime
        .apply(config_start(
            giganto.addr,
            &[("kind_a", &a)],
            StartPosition::End,
        ))
        .await;
    let start = record("kind_a", &a, length(&a));
    wait_for_checkpoint(&state, "kind_a", &start, WAIT).await;
    giganto.withhold_acks(&["kind_a"]);
    append(&a, "a3")?;
    append(&a, "a4")?;
    wait_for_lines(&giganto, "kind_a", &["a3", "a4"]).await;
    assert_eq!(giganto.lines("kind_a"), ["a3", "a4"]);
    // A crash: the runtime is dropped without a shutdown.
    drop(runtime);
    sleep(SETTLE).await;
    assert_eq!(checkpoint(&state, "kind_a"), Some(start));

    giganto.withhold_acks(&[]);
    let streams = giganto.streams_of("kind_a").len();
    let mut runtime = self::runtime(&files.files, &reload, &state);
    runtime
        .apply(config_start(
            giganto.addr,
            &[("kind_a", &a)],
            StartPosition::End,
        ))
        .await;
    wait_for("the new stream receives a3 and a4", WAIT, || {
        lines_from(&giganto, "kind_a", streams) == ["a3", "a4"]
    })
    .await;
    sleep(SETTLE).await;
    assert_eq!(lines_from(&giganto, "kind_a", streams), ["a3", "a4"]);
    runtime.shutdown().await;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn a_restart_after_a_clean_stop_sends_exactly_the_new_lines() -> Result<()> {
    let (_pki, giganto, files) = setup()?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1", "a2"])?;
    let state = logs.state();
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload, &state);
    runtime.apply(config(giganto.addr, &[("kind_a", &a)])).await;
    wait_for_lines(&giganto, "kind_a", &["a1", "a2"]).await;
    runtime.shutdown().await;
    assert_eq!(
        checkpoint(&state, "kind_a"),
        Some(record("kind_a", &a, length(&a)))
    );

    append(&a, "a3")?;
    append(&a, "a4")?;
    let streams = giganto.streams_of("kind_a").len();
    let mut runtime = self::runtime(&files.files, &reload, &state);
    runtime.apply(config(giganto.addr, &[("kind_a", &a)])).await;
    wait_for_lines(&giganto, "kind_a", &["a3", "a4"]).await;
    sleep(SETTLE).await;
    assert_eq!(lines_from(&giganto, "kind_a", streams), ["a3", "a4"]);
    runtime.shutdown().await;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn rename_and_copy_truncate_rotations_send_each_line_once() -> Result<()> {
    let (logs_capture, _guard) = Logs::capture();
    let (_pki, giganto, files) = setup()?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1"])?;
    let state = logs.state();
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload, &state);
    runtime.apply(config(giganto.addr, &[("kind_a", &a)])).await;
    wait_for_lines(&giganto, "kind_a", &["a1"]).await;

    // A rename rotation, with a late write to the renamed file.
    let renamed = logs.path("a.log.1");
    std::fs::rename(&a, &renamed)?;
    std::fs::write(&a, "b1\nb2\nb3\n")?;
    append(&renamed, "a2")?;
    wait_for_lines(&giganto, "kind_a", &["a2", "b1", "b2", "b3"]).await;
    wait_for_checkpoint(&state, "kind_a", &record("kind_a", &a, length(&a)), WAIT).await;

    // A copy-truncate once the reader is at EOF.
    copy_truncate(&a, &["c1"])?;
    wait_for_lines(&giganto, "kind_a", &["c1"]).await;
    wait_for_log(
        &logs_capture,
        &format!(
            "{} for kind_a was truncated; reading it again from its beginning",
            a.display()
        ),
    )
    .await;
    sleep(SETTLE).await;
    assert_eq!(
        giganto.lines("kind_a"),
        ["a1", "a2", "b1", "b2", "b3", "c1"]
    );
    runtime.shutdown().await;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn a_closed_connection_sends_the_unacknowledged_lines_again() -> Result<()> {
    let (_pki, giganto, files) = setup()?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1"])?;
    let state = logs.state();
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload, &state);
    runtime.apply(config(giganto.addr, &[("kind_a", &a)])).await;
    wait_for_lines(&giganto, "kind_a", &["a1"]).await;
    wait_for_checkpoint(&state, "kind_a", &record("kind_a", &a, length(&a)), WAIT).await;

    giganto.withhold_acks(&["kind_a"]);
    append(&a, "a2")?;
    append(&a, "a3")?;
    wait_for_lines(&giganto, "kind_a", &["a2", "a3"]).await;
    giganto.close_connections();
    append(&a, "a4")?;
    wait_for("a new stream carries a4", WAIT, || {
        giganto
            .streams_of("kind_a")
            .get(1)
            .is_some_and(|stream| stream.lines().contains(&"a4".to_string()))
    })
    .await;
    // The new stream starts at the acknowledged position.
    assert_eq!(giganto.streams_of("kind_a")[1].lines(), ["a2", "a3", "a4"]);

    // A stream reopened while the file is unchanged replays only the suffix
    // after the acknowledged position, and then follows new lines.
    giganto.withhold_acks(&[]);
    append(&a, "a5")?;
    wait_for_lines(&giganto, "kind_a", &["a5"]).await;
    wait_for_checkpoint(&state, "kind_a", &record("kind_a", &a, length(&a)), WAIT).await;
    giganto.stop_stream_of("kind_a")?;
    append(&a, "a6")?;
    wait_for("a third stream carries a6", WAIT, || {
        giganto
            .streams_of("kind_a")
            .get(2)
            .is_some_and(|stream| stream.lines().contains(&"a6".to_string()))
    })
    .await;
    sleep(SETTLE).await;
    assert_eq!(giganto.streams_of("kind_a")[2].lines(), ["a6"]);
    assert_eq!(
        giganto
            .lines("kind_a")
            .iter()
            .filter(|line| *line == "a1")
            .count(),
        1
    );
    runtime.shutdown().await;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn an_idle_collector_sends_the_unacknowledged_lines_again() -> Result<()> {
    let (_pki, giganto, files) = setup()?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1"])?;
    let state = logs.state();
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload, &state);
    runtime.apply(config(giganto.addr, &[("kind_a", &a)])).await;
    wait_for_lines(&giganto, "kind_a", &["a1"]).await;
    wait_for_checkpoint(&state, "kind_a", &record("kind_a", &a, length(&a)), WAIT).await;

    // The file stays unchanged after each failure: no later write finds
    // the failed stream.
    giganto.withhold_acks(&["kind_a"]);
    append(&a, "a2")?;
    wait_for_lines(&giganto, "kind_a", &["a2"]).await;
    giganto.stop_stream_of("kind_a")?;
    wait_for("a second stream carries a2", WAIT, || {
        giganto
            .streams_of("kind_a")
            .get(1)
            .is_some_and(|stream| stream.lines() == ["a2"])
    })
    .await;

    giganto.close_connections();
    wait_for("a third stream carries a2", WAIT, || {
        giganto
            .streams_of("kind_a")
            .get(2)
            .is_some_and(|stream| stream.lines() == ["a2"])
    })
    .await;
    assert_eq!(giganto.connections(), 2);

    giganto.withhold_acks(&[]);
    append(&a, "a3")?;
    wait_for_lines(&giganto, "kind_a", &["a3"]).await;
    wait_for_checkpoint(&state, "kind_a", &record("kind_a", &a, length(&a)), WAIT).await;
    runtime.shutdown().await;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn a_delayed_old_ack_does_not_move_a_truncated_files_checkpoint() -> Result<()> {
    let (logs_capture, _guard) = Logs::capture();
    let (_pki, giganto, files) = setup()?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1"])?;
    let state = logs.state();
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload, &state);
    runtime.apply(config(giganto.addr, &[("kind_a", &a)])).await;
    wait_for_lines(&giganto, "kind_a", &["a1"]).await;
    wait_for_checkpoint(&state, "kind_a", &record("kind_a", &a, length(&a)), WAIT).await;

    // Old batches await their ACKs as the file is truncated.
    giganto.hold_acks(&["kind_a"]).await;
    append(&a, "a2 a longer line")?;
    append(&a, "a3 a longer line")?;
    wait_for_lines(
        &giganto,
        "kind_a",
        &["a2 a longer line", "a3 a longer line"],
    )
    .await;
    copy_truncate(&a, &[])?;
    wait_for_log(&logs_capture, "was truncated").await;
    let epoch = record("kind_a", &a, 0);
    wait_for_checkpoint(&state, "kind_a", &epoch, WAIT).await;

    // The old ACKs arrive after the transition: they acknowledge nothing.
    giganto.release_acks().await;
    sleep(SETTLE).await;
    assert_eq!(checkpoint(&state, "kind_a"), Some(epoch));

    // A new line acknowledged moves it.
    append(&a, "b1")?;
    wait_for_lines(&giganto, "kind_a", &["b1"]).await;
    wait_for_checkpoint(&state, "kind_a", &record("kind_a", &a, length(&a)), WAIT).await;
    runtime.shutdown().await;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn a_failing_epoch_save_holds_back_the_new_content() -> Result<()> {
    let (logs_capture, _guard) = Logs::capture();
    let (_pki, giganto, files) = setup()?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1 a longer line", "a2 a longer line"])?;
    let state = logs.state();
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload, &state);
    runtime.apply(config(giganto.addr, &[("kind_a", &a)])).await;
    wait_for_lines(&giganto, "kind_a", &["a2 a longer line"]).await;
    wait_for_checkpoint(&state, "kind_a", &record("kind_a", &a, length(&a)), WAIT).await;

    let obstacle = checkpoint_file(&state, "kind_a").with_extension("json.tmp");
    std::fs::create_dir(&obstacle)?;
    copy_truncate(&a, &["b1"])?;
    wait_for_log(&logs_capture, "was truncated").await;
    // More than two retries of every 3 s.
    sleep(Duration::from_secs(7)).await;
    assert!(!giganto.lines("kind_a").contains(&"b1".to_string()));

    std::fs::remove_dir(&obstacle)?;
    wait_for_lines(&giganto, "kind_a", &["b1"]).await;
    wait_for_checkpoint(&state, "kind_a", &record("kind_a", &a, length(&a)), WAIT).await;
    runtime.shutdown().await;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn new_content_after_a_truncation_survives_a_crash_before_its_first_ack() -> Result<()> {
    let (logs_capture, _guard) = Logs::capture();
    let (_pki, giganto, files) = setup()?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1"])?;
    let state = logs.state();
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload, &state);
    runtime.apply(config(giganto.addr, &[("kind_a", &a)])).await;
    wait_for_lines(&giganto, "kind_a", &["a1"]).await;
    giganto.hold_acks(&["kind_a"]).await;
    append(&a, "a2 a longer line")?;
    append(&a, "a3 a longer line")?;
    wait_for_lines(&giganto, "kind_a", &["a3 a longer line"]).await;
    let old_offset = length(&a);

    copy_truncate(&a, &["b1"])?;
    wait_for_log(&logs_capture, "was truncated").await;
    wait_for_lines(&giganto, "kind_a", &["b1"]).await;
    // New batches await their first ACK: no save carries a position from
    // before the truncation.
    let epoch = record("kind_a", &a, 0);
    let deadline = Instant::now() + SETTLE;
    while Instant::now() < deadline {
        assert_eq!(checkpoint(&state, "kind_a"), Some(epoch.clone()));
        sleep(Duration::from_millis(50)).await;
    }

    // The new content grows past the old offset, and the process crashes.
    let mut count = 2;
    while length(&a) <= old_offset {
        append(&a, &format!("b{count}"))?;
        count += 1;
    }
    let last = format!("b{}", count - 1);
    wait_for_lines(&giganto, "kind_a", &[&last]).await;
    drop(runtime);
    sleep(SETTLE).await;
    assert_eq!(checkpoint(&state, "kind_a"), Some(epoch));

    let streams = giganto.streams_of("kind_a").len();
    giganto.release_acks().await;
    let mut runtime = self::runtime(&files.files, &reload, &state);
    runtime.apply(config(giganto.addr, &[("kind_a", &a)])).await;
    let expected = (1..count)
        .map(|index| format!("b{index}"))
        .collect::<Vec<_>>();
    wait_for("the restart sends the new content", WAIT, || {
        lines_from(&giganto, "kind_a", streams) == expected
    })
    .await;
    runtime.shutdown().await;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn a_new_connection_after_a_truncation_carries_only_new_lines() -> Result<()> {
    let (logs_capture, _guard) = Logs::capture();
    let (_pki, giganto, files) = setup()?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1 a longer line", "a2 a longer line"])?;
    let state = logs.state();
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload, &state);
    runtime.apply(config(giganto.addr, &[("kind_a", &a)])).await;
    wait_for_lines(&giganto, "kind_a", &["a2 a longer line"]).await;
    giganto.withhold_acks(&["kind_a"]);
    append(&a, "a3 a longer line")?;
    wait_for_lines(&giganto, "kind_a", &["a3 a longer line"]).await;

    copy_truncate(&a, &["b1"])?;
    wait_for_log(&logs_capture, "was truncated").await;
    wait_for_lines(&giganto, "kind_a", &["b1"]).await;
    giganto.close_connections();
    append(&a, "b2")?;
    wait_for("a new stream carries b2", WAIT, || {
        giganto
            .streams_of("kind_a")
            .get(1)
            .is_some_and(|stream| stream.lines().contains(&"b2".to_string()))
    })
    .await;
    assert_eq!(giganto.streams_of("kind_a")[1].lines(), ["b1", "b2"]);
    giganto.withhold_acks(&[]);
    runtime.shutdown().await;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn a_file_truncated_while_stopped_saves_its_epoch_before_sending() -> Result<()> {
    let (logs_capture, _guard) = Logs::capture();
    let (_pki, giganto, files) = setup()?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1 a longer line", "a2 a longer line"])?;
    let state = logs.state();
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload, &state);
    runtime.apply(config(giganto.addr, &[("kind_a", &a)])).await;
    wait_for_lines(&giganto, "kind_a", &["a2 a longer line"]).await;
    runtime.shutdown().await;

    copy_truncate(&a, &["b1"])?;
    // The epoch's save fails at first: nothing is sent until it lands.
    let obstacle = checkpoint_file(&state, "kind_a").with_extension("json.tmp");
    std::fs::create_dir(&obstacle)?;
    giganto.withhold_acks(&["kind_a"]);
    let streams = giganto.streams_of("kind_a").len();
    let opened = giganto.streams().len();
    let mut runtime = self::runtime(&files.files, &reload, &state);
    runtime.apply(config(giganto.addr, &[("kind_a", &a)])).await;
    wait_for_log(&logs_capture, "was truncated").await;
    sleep(Duration::from_secs(4)).await;
    assert_eq!(giganto.streams().len(), opened, "no stream is opened");

    std::fs::remove_dir(&obstacle)?;
    wait_for_lines(&giganto, "kind_a", &["b1"]).await;
    assert_eq!(checkpoint(&state, "kind_a"), Some(record("kind_a", &a, 0)));
    assert_eq!(lines_from(&giganto, "kind_a", streams), ["b1"]);
    giganto.withhold_acks(&[]);
    runtime.shutdown().await;
    Ok(())
}

/// With the first save of the starting position failing, nothing is sent
/// until it lands; after a crash before the first data ACK, the lines
/// appended since are sent.
#[cfg(unix)]
async fn initial_save_failure_then_crash(corrupt: bool) -> Result<()> {
    let (logs_capture, _guard) = Logs::capture();
    let (_pki, giganto, files) = setup()?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1"])?;
    let state = logs.state();
    let file = checkpoint_file(&state, "kind_a");
    std::fs::create_dir_all(file.parent().context("a parent")?)?;
    if corrupt {
        std::fs::write(&file, b"{")?;
    }
    let obstacle = file.with_extension("json.tmp");
    std::fs::create_dir(&obstacle)?;
    giganto.withhold_acks(&["kind_a"]);
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload, &state);
    runtime
        .apply(config_start(
            giganto.addr,
            &[("kind_a", &a)],
            StartPosition::End,
        ))
        .await;
    // The starting position is chosen before its first save fails.
    wait_for_log(&logs_capture, "Cannot save the checkpoint of kind_a").await;
    append(&a, "a2")?;
    sleep(Duration::from_secs(7)).await;
    assert!(giganto.streams().is_empty(), "{:?}", giganto.streams());

    std::fs::remove_dir(&obstacle)?;
    // The starting position chosen before the save first failed.
    wait_for_checkpoint(&state, "kind_a", &record("kind_a", &a, 3), WAIT).await;
    wait_for_lines(&giganto, "kind_a", &["a2"]).await;
    append(&a, "a3")?;
    wait_for_lines(&giganto, "kind_a", &["a3"]).await;
    drop(runtime);
    sleep(SETTLE).await;

    giganto.withhold_acks(&[]);
    let streams = giganto.streams_of("kind_a").len();
    let mut runtime = self::runtime(&files.files, &reload, &state);
    runtime
        .apply(config_start(
            giganto.addr,
            &[("kind_a", &a)],
            StartPosition::End,
        ))
        .await;
    wait_for("the restart sends a2 and a3", WAIT, || {
        lines_from(&giganto, "kind_a", streams) == ["a2", "a3"]
    })
    .await;
    assert!(!giganto.lines("kind_a").contains(&"a1".to_string()));
    runtime.shutdown().await;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn a_failing_initial_save_holds_back_start_end() -> Result<()> {
    initial_save_failure_then_crash(false).await
}

#[cfg(unix)]
#[tokio::test]
async fn a_failing_initial_save_holds_back_a_corrupt_checkpoints_replacement() -> Result<()> {
    initial_save_failure_then_crash(true).await
}

#[tokio::test]
async fn timestamps_strictly_increase_within_a_batch() -> Result<()> {
    let (_pki, giganto, files) = setup()?;
    let logs = LogFiles::new()?;
    let lines = (0..500)
        .map(|index| format!("l{index}"))
        .collect::<Vec<_>>();
    let a = logs.create(
        "a.log",
        &lines.iter().map(String::as_str).collect::<Vec<_>>(),
    )?;
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload, &logs.state());
    runtime.apply(config(giganto.addr, &[("kind_a", &a)])).await;
    wait_for("every line arrives", WAIT, || {
        giganto.lines("kind_a").len() == lines.len()
    })
    .await;
    let timestamps = giganto
        .streams_of("kind_a")
        .iter()
        .flat_map(|stream| stream.timestamps.clone())
        .collect::<Vec<_>>();
    assert_eq!(timestamps.len(), lines.len());
    assert!(timestamps.windows(2).all(|pair| pair[0] < pair[1]));
    runtime.shutdown().await;
    Ok(())
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_symlink_into_proc_is_refused() -> Result<()> {
    let (logs_capture, _guard) = Logs::capture();
    let (_pki, giganto, files) = setup()?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1"])?;
    let link = logs.path("status.log");
    std::os::unix::fs::symlink("/proc/self/status", &link)?;
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload, &logs.state());
    runtime
        .apply(config(giganto.addr, &[("kind_a", &a), ("kind_p", &link)]))
        .await;
    wait_for_lines(&giganto, "kind_a", &["a1"]).await;
    let expected = format!(
        "Collector kind_p for {}: the file lies under the refused directory /proc",
        link.display()
    );
    wait_for_log(&logs_capture, &expected).await;
    sleep(SETTLE).await;
    assert!(giganto.streams_of("kind_p").is_empty());
    assert_eq!(giganto.lines("kind_p"), Vec::<String>::new());
    runtime.shutdown().await;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn a_blocked_write_does_not_hold_back_the_release_of_a_rotated_away_file() -> Result<()> {
    let (_pki, giganto, files) = setup()?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1"])?;
    let state = logs.state();
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload, &state);
    runtime.apply(config(giganto.addr, &[("kind_a", &a)])).await;
    wait_for_lines(&giganto, "kind_a", &["a1"]).await;
    wait_for_checkpoint(&state, "kind_a", &record("kind_a", &a, length(&a)), WAIT).await;

    // The ACK of the last line of the file rotated away is held back, so
    // the file is held once the collector reads the new one.
    giganto.hold_acks(&["kind_a"]).await;
    append(&a, "a2")?;
    wait_for_lines(&giganto, "kind_a", &["a2"]).await;
    giganto.pause_reading_after("kind_a", "b1");
    let renamed = logs.path("a.log.1");
    std::fs::rename(&a, &renamed)?;
    std::fs::write(&a, "b1\n")?;
    wait_for_lines(&giganto, "kind_a", &["b1"]).await;
    assert!(is_open(&renamed));

    // A batch larger than the stream's receive window, with nothing after
    // it: its write waits for the server, which reads no further, and the
    // reader waits at the end of the file. The reader finds the lines at
    // its next check, at most 3 seconds later.
    let filler = "x".repeat(3400);
    let mut lines = (0..1000)
        .map(|index| format!("c{index:04}{filler}"))
        .collect::<Vec<_>>()
        .join("\n");
    lines.push('\n');
    std::fs::OpenOptions::new()
        .append(true)
        .open(&a)
        .and_then(|mut file| std::io::Write::write_all(&mut file, lines.as_bytes()))?;
    sleep(Duration::from_secs(3) + SETTLE).await;

    // The held ACKs arrive while the write is still blocked: the
    // acknowledged position leaves the rotated-away file, which is
    // released within about three seconds.
    giganto.release_acks().await;
    let released = Instant::now();
    wait_for(
        "the rotated-away file is released",
        Duration::from_millis(4500),
        || !is_open(&renamed),
    )
    .await;
    assert_eq!(giganto.lines("kind_a"), ["a1", "a2", "b1"]);
    sleep(Duration::from_secs(3).saturating_sub(released.elapsed())).await;
    assert_eq!(
        giganto.lines("kind_a"),
        ["a1", "a2", "b1"],
        "the write stays blocked beyond three seconds"
    );

    giganto.resume_reading();
    wait_for("the batch arrives", WAIT, || {
        giganto.lines("kind_a").len() == 1003
    })
    .await;
    wait_for_checkpoint(&state, "kind_a", &record("kind_a", &a, length(&a)), WAIT).await;
    runtime.shutdown().await;
    Ok(())
}
