//! Tests of the remote-mode collector runtime against an in-process
//! Giganto-like QUIC server.
//!
//! The server completes giganto-client's handshake with a configurable
//! version requirement, verifies client certificates against an rcgen CA,
//! and reads every stream's record header and batches. It sends a data ACK
//! for every record and the close ACK for every close marker, unless told to
//! withhold the close ACK, and can stop a stream or close a connection.

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
    /// When a connection failed before its Giganto handshake, as a TLS
    /// refusal does.
    refused: Mutex<Vec<Instant>>,
    /// When a Giganto handshake was refused.
    version_refused: Mutex<Vec<Instant>>,
    connections: Mutex<Vec<quinn::Connection>>,
    streams: Mutex<Vec<StreamRecord>>,
    /// How many new streams to stop as soon as their header arrives.
    stop_next: Mutex<usize>,
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
            refused: Mutex::new(Vec::new()),
            version_refused: Mutex::new(Vec::new()),
            connections: Mutex::new(Vec::new()),
            streams: Mutex::new(Vec::new()),
            stop_next: Mutex::new(0),
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
    mut send: SendStream,
    mut recv: RecvStream,
) {
    let mut header = [0_u8; 4];
    if receive_record_header(&mut recv, &mut header).await.is_err() {
        return;
    }
    let stop = CancellationToken::new();
    let index = {
        let mut streams = lock(&state.streams);
        streams.push(StreamRecord {
            connection,
            header: u32::from_le_bytes(header),
            accepted_at: Instant::now(),
            records: Vec::new(),
            close_marker: false,
            ended: None,
            stop: stop.clone(),
        });
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
        let mut buf = Vec::new();
        let read = tokio::select! {
            read = recv_raw(&mut recv, &mut buf) => read,
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
                lock(&state.streams)[index]
                    .records
                    .push((log.kind, String::from_utf8_lossy(&log.log).into_owned()));
            }
            let _ = send.write_all(&timestamp.to_be_bytes()).await;
        }
    };
    lock(&state.streams)[index].ended = Some(end);
}

/// The log files of a test.
struct LogFiles {
    dir: TempDir,
}

impl LogFiles {
    fn new() -> Result<Self> {
        Ok(Self {
            dir: tempfile::tempdir()?,
        })
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
    RemoteConfig {
        giganto_ingest_srv_addr: addr,
        giganto_name: SERVER_NAME.to_string(),
        collectors: collectors
            .iter()
            .map(|(kind, path)| CollectorConfig {
                collector_type: CollectorType::Log,
                kind: (*kind).to_string(),
                path: path.to_path_buf(),
                start: StartPosition::End,
            })
            .collect(),
    }
}

fn runtime(files: &TlsFiles, reload: &ReloadSignal) -> CollectorRuntime {
    CollectorRuntime::new(files.clone(), reload.clone()).with_retry_interval(RETRY)
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
    let mut runtime = runtime(&files.files, &reload);

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
    let mut runtime = runtime(&files.files, &reload);

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
    let mut runtime = runtime(&files.files, &reload);

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
    let mut runtime = runtime(&files.files, &reload);

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
    let mut runtime = runtime(&files.files, &reload);

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
    let mut runtime = runtime(&files.files, &reload);

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
    let mut runtime = runtime(&files.files, &reload);

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
    let mut runtime = runtime(&files.files, &reload);

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
    let mut runtime = runtime(&files.files, &reload);

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
    let mut runtime =
        CollectorRuntime::new(files.files.clone(), reload.clone()).with_retry_interval(retry);

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
    let mut runtime = runtime(&files.files, &reload);

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
    let (_pki, giganto, files) = setup()?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1"])?;
    let b = logs.create("b.log", &["b1"])?;
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload);

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

    giganto.withhold(Withhold::Nothing);
    runtime.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn shutdown_without_close_acks_returns_after_the_deadline() -> Result<()> {
    let (_pki, giganto, files) = setup()?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1"])?;
    let b = logs.create("b.log", &["b1"])?;
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload);

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
    Ok(())
}

#[tokio::test]
async fn shutdown_after_a_dropped_apply_stops_every_collector() -> Result<()> {
    let (logs_capture, _guard) = Logs::capture();
    let (_pki, giganto, files) = setup()?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1"])?;
    let b = logs.create("b.log", &["b1"])?;
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload);

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

[[collectors]]
type = "log"
kind = "kind_b"
path = "{}"
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
    Ok(())
}
