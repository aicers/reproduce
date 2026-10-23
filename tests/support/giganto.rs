//! An in-process Giganto-like QUIC ingest server.
//!
//! The server completes giganto-client's handshake with a configurable
//! version requirement, verifies client certificates against an rcgen CA,
//! and reads every stream's record header and batches, decoding `Log` and
//! `OpLog` records by the stream's header. It sends a data ACK
//! for every record and the close ACK for every close marker, unless told to
//! withhold the data ACKs or the close ACK, or to hold data ACKs back and send
//! them later, and can stop reading a kind's streams, stop a stream, close a
//! connection, and stop and start again on the same address.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use anyhow::{Context, Result};
use giganto_client::{
    RawEventKind,
    connection::server_handshake,
    frame::recv_raw,
    ingest::log::{Log, OpLog},
    ingest::receive_record_header,
};
use quinn::{Endpoint, RecvStream, SendStream, VarInt};
use reproduce::sender::CHANNEL_CLOSE_TIMESTAMP;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep};
use tokio_util::sync::CancellationToken;

use super::{Identity, Pki, server_config_trusting};

/// The version requirement Giganto 0.31.0 accepts.
pub const GIGANTO_VERSION_REQ: &str = ">=0.28.0";
/// What the server keys the journal collector's stream by, in place of a
/// kind; no log kind can contain `@`.
pub const JOURNAL: &str = "@journal";

/// Whose close ACKs the server withholds.
#[derive(Clone, Debug, Default)]
pub enum Withhold {
    #[default]
    Nothing,
    All,
    Kinds(HashSet<String>),
}

impl Withhold {
    pub fn holds(&self, kind: Option<&str>) -> bool {
        match self {
            Self::Nothing => false,
            Self::All => true,
            Self::Kinds(kinds) => kind.is_some_and(|kind| kinds.contains(kind)),
        }
    }
}

/// One stream the server accepted.
#[derive(Clone, Debug)]
pub struct StreamRecord {
    pub connection: usize,
    pub header: u32,
    pub accepted_at: Instant,
    /// `(kind, line)` of every `Log` record received, and
    /// `(JOURNAL, contents)` of every `OpLog` record.
    pub records: Vec<(String, String)>,
    /// Every `OpLog` record received.
    pub op_logs: Vec<OpLog>,
    /// The timestamp of every record received.
    pub timestamps: Vec<i64>,
    pub close_marker: bool,
    /// How the stream ended, if it has.
    pub ended: Option<String>,
    pub stop: CancellationToken,
}

impl StreamRecord {
    /// The kind of a `Log` stream, once a record arrived, or [`JOURNAL`]
    /// for an `OpLog` stream.
    pub fn kind(&self) -> Option<&str> {
        if self.header == op_log_header() {
            return Some(JOURNAL);
        }
        self.records.first().map(|(kind, _)| kind.as_str())
    }

    pub fn lines(&self) -> Vec<String> {
        self.records.iter().map(|(_, line)| line.clone()).collect()
    }
}

pub struct GigantoState {
    version_req: Mutex<String>,
    pub withhold: watch::Sender<Withhold>,
    /// The kinds whose data ACKs are withheld; their records are still
    /// stored.
    withhold_acks: Mutex<HashSet<String>>,
    /// When a connection failed before its Giganto handshake, as a TLS
    /// refusal does.
    refused: Mutex<Vec<Instant>>,
    /// When a Giganto handshake was refused.
    version_refused: Mutex<Vec<Instant>>,
    /// Every connection accepted, by its index; `None` once the server
    /// stopped, so that nothing holds its socket.
    connections: Mutex<Vec<Option<quinn::Connection>>>,
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
pub struct Giganto {
    pub addr: SocketAddr,
    server_config: Mutex<quinn::ServerConfig>,
    pub state: Arc<GigantoState>,
    /// The endpoint and its accept task, while the server runs.
    running: Option<(Endpoint, JoinHandle<()>)>,
}

impl Giganto {
    pub fn start(pki: &Pki) -> Result<Self> {
        let config = server_config_trusting(&pki.server, &pki.ca)?;
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
        let endpoint = Endpoint::server(
            config.clone(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        )?;
        let addr = endpoint.local_addr()?;
        let task = tokio::spawn(accept(endpoint.clone(), state.clone()));
        Ok(Self {
            addr,
            server_config: Mutex::new(config),
            state,
            running: Some((endpoint, task)),
        })
    }

    /// Closes every connection and stops listening, keeping what the server
    /// received.
    pub async fn stop(&mut self) {
        if let Some((endpoint, task)) = self.running.take() {
            task.abort();
            let _ = task.await;
            self.close_connections();
            for connection in lock(&self.state.connections).iter_mut() {
                connection.take();
            }
            // Ends the streams' tasks also where they wait, so that no
            // stream holds the socket either.
            for stream in lock(&self.state.streams).iter() {
                stream.stop.cancel();
            }
            endpoint.close(0u32.into(), b"stopped");
            endpoint.wait_idle().await;
        }
    }

    /// Starts serving again on the same address after [`Giganto::stop`].
    /// The port is bound again as soon as the stopped endpoint releases it.
    pub async fn restart(&mut self) -> Result<()> {
        let config = lock(&self.server_config).clone();
        let deadline = Instant::now() + Duration::from_secs(30);
        let endpoint = loop {
            match Endpoint::server(config.clone(), self.addr) {
                Ok(endpoint) => break endpoint,
                Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
                    anyhow::ensure!(Instant::now() < deadline, "{} stays in use", self.addr);
                    sleep(Duration::from_millis(50)).await;
                }
                Err(error) => return Err(error.into()),
            }
        };
        let task = tokio::spawn(accept(endpoint.clone(), self.state.clone()));
        self.running = Some((endpoint, task));
        Ok(())
    }

    /// Verifies client certificates against `client_ca` from now on.
    pub fn trust(&self, server: &Identity, client_ca: &str) -> Result<()> {
        let config = server_config_trusting(server, client_ca)?;
        if let Some((endpoint, _)) = &self.running {
            endpoint.set_server_config(Some(config.clone()));
        }
        *lock(&self.server_config) = config;
        Ok(())
    }

    pub fn set_version_req(&self, version_req: &str) {
        *lock(&self.state.version_req) = version_req.to_string();
    }

    pub fn withhold(&self, withhold: Withhold) {
        self.state.withhold.send_replace(withhold);
    }

    /// Withholds the data ACKs of `kinds` from now on, and only theirs.
    pub fn withhold_acks(&self, kinds: &[&str]) {
        *lock(&self.state.withhold_acks) = kinds.iter().map(|kind| (*kind).to_string()).collect();
    }

    /// Holds back the data ACKs of `kinds` from now on, to be sent by
    /// [`release_acks`](Self::release_acks).
    pub async fn hold_acks(&self, kinds: &[&str]) {
        self.state.hold.lock().await.kinds = kinds.iter().map(|kind| (*kind).to_string()).collect();
    }

    /// Sends every held data ACK, in order, on the stream it is for, and
    /// holds nothing back any more.
    pub async fn release_acks(&self) {
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
    pub fn pause_reading_after(&self, kind: &str, line: &str) {
        *lock(&self.state.pause_after) = Some((kind.to_string(), line.to_string()));
    }

    /// Reads every stream again.
    pub fn resume_reading(&self) {
        *lock(&self.state.pause_after) = None;
        self.state.paused.send_replace(HashSet::new());
    }

    pub fn stop_next_streams(&self, count: usize) {
        *lock(&self.state.stop_next) = count;
    }

    pub fn connections(&self) -> usize {
        lock(&self.state.connections).len()
    }

    pub fn connection(&self, index: usize) -> quinn::Connection {
        lock(&self.state.connections)[index]
            .clone()
            .expect("a connection of the running server")
    }

    pub fn close_connections(&self) {
        for connection in lock(&self.state.connections).iter().flatten() {
            connection.close(0u32.into(), b"server-gone");
        }
    }

    pub fn refused(&self) -> Vec<Instant> {
        lock(&self.state.refused).clone()
    }

    pub fn version_refused(&self) -> Vec<Instant> {
        lock(&self.state.version_refused).clone()
    }

    pub fn streams(&self) -> Vec<StreamRecord> {
        lock(&self.state.streams).clone()
    }

    /// The streams whose records carry `kind`.
    pub fn streams_of(&self, kind: &str) -> Vec<StreamRecord> {
        self.streams()
            .into_iter()
            .filter(|stream| stream.kind() == Some(kind))
            .collect()
    }

    /// Every line received for `kind`, in stream order.
    pub fn lines(&self, kind: &str) -> Vec<String> {
        self.streams_of(kind)
            .iter()
            .flat_map(StreamRecord::lines)
            .collect()
    }

    /// Stops the latest stream carrying `kind`.
    pub fn stop_stream_of(&self, kind: &str) -> Result<()> {
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
        if let Some((endpoint, task)) = self.running.take() {
            task.abort();
            endpoint.close(0u32.into(), b"stopped");
        }
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
        connections.push(Some(connection.clone()));
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
            op_logs: Vec::new(),
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
            } else if let Some((kind, line, op_log)) = decode(header, &data) {
                let withheld = lock(&state.withhold_acks).contains(&kind);
                state.pause_if_after(&kind, &line);
                {
                    let mut streams = lock(&state.streams);
                    streams[index].timestamps.push(timestamp);
                    streams[index].records.push((kind.clone(), line));
                    streams[index].op_logs.extend(op_log);
                }
                if withheld {
                    continue;
                }
                // Held under the lock, so a release sends every older ACK
                // first.
                let mut hold = state.hold.lock().await;
                if hold.kinds.contains(&kind) {
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

impl GigantoState {
    /// Pauses reading the streams of `kind` if `line` of `kind` is the
    /// record set by [`Giganto::pause_reading_after`].
    fn pause_if_after(&self, kind: &str, line: &str) {
        let mut pause_after = lock(&self.pause_after);
        if pause_after
            .as_ref()
            .is_some_and(|(paused, after)| paused == kind && after == line)
        {
            *pause_after = None;
            self.paused.send_modify(|paused| {
                paused.insert(kind.to_string());
            });
        }
    }
}

/// Decodes a record of a stream with `header` into its kind and line, and,
/// for an `OpLog`, the record.
pub fn decode(header: [u8; 4], data: &[u8]) -> Option<(String, String, Option<OpLog>)> {
    if u32::from_le_bytes(header) == op_log_header() {
        let op_log = bincode::deserialize::<OpLog>(data).ok()?;
        return Some((JOURNAL.to_string(), op_log.contents.clone(), Some(op_log)));
    }
    let log = bincode::deserialize::<Log>(data).ok()?;
    Some((
        log.kind,
        String::from_utf8_lossy(&log.log).into_owned(),
        None,
    ))
}

pub fn log_header() -> u32 {
    u32::from(RawEventKind::Log)
}

pub fn op_log_header() -> u32 {
    u32::from(RawEventKind::OpLog)
}
