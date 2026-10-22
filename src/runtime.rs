//! The collector runtime of remote mode.
//!
//! [`CollectorRuntime`] puts each configuration the Central Manager provides
//! in force: one collector per `[[collectors]]` entry, each reading one file
//! and sending its lines as Giganto `Log` records on a stream of its own, and
//! every stream sharing one Giganto ingest connection.
//!
//! The runtime publishes the current connection in a watch channel together
//! with a sequence number it increments for every connection it creates. A
//! collector opens its stream on the published connection; when the runtime
//! closes or cancels that connection for an address change, the collector
//! waits for a connection with a higher sequence number and opens its stream
//! there.

use std::collections::{HashMap, HashSet};
use std::error::Error as StdError;
use std::fmt::Write as _;
use std::io;
use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use giganto_client::{RawEventKind, frame::SendError};
use quinn::WriteError;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::collector::POLLING_INTERVAL;
use crate::collector::log::LogCollector;
use crate::config::remote::{CollectorConfig, RemoteConfig};
use crate::controller::{PipelineError, PipelineSender, run_pipeline_with_sender};
use crate::manager::{ConfigRuntime, TlsFiles};
use crate::reload::ReloadSignal;
use crate::sender::{
    AckDelivery, CHANNEL_CLOSE_TIMEOUT, CloseAck, ConnectionConfig, GigantoConnection,
    GigantoStream, INTERVAL, ReconnectOutcome, SenderError, StreamErrorPolicy,
};

/// What identifies a collector: its kind and its path.
type Key = (String, PathBuf);

/// The connection the collectors open their streams on.
#[derive(Clone, Debug)]
struct Published {
    /// Incremented for every connection the runtime creates.
    sequence: u64,
    connection: GigantoConnection,
}

type PublishedSender = watch::Sender<Option<Published>>;
type PublishedReceiver = watch::Receiver<Option<Published>>;

/// Runs the collectors of the configuration in force over one Giganto
/// connection.
///
/// Dropping the runtime without [`shutdown`](Self::shutdown) aborts its tasks
/// without closing any stream.
pub struct CollectorRuntime {
    files: TlsFiles,
    reload: ReloadSignal,
    retry_interval: Duration,
    /// The configuration in force.
    config: Option<RemoteConfig>,
    /// The task making the current connection, and the token that cancels
    /// connecting and the connection's reconnects.
    connection: Option<ConnectionTask>,
    published: PublishedSender,
    sequence: u64,
    collectors: HashMap<Key, CollectorHandle>,
    /// Collectors whose stop is set, until they end.
    stopping: Vec<CollectorHandle>,
}

struct ConnectionTask {
    token: CancellationToken,
    task: JoinHandle<()>,
}

/// The runtime's side of one collector.
struct CollectorHandle {
    kind: String,
    path: PathBuf,
    stop: watch::Sender<bool>,
    /// The token of the collector's stream.
    token: CancellationToken,
    task: JoinHandle<()>,
}

impl CollectorHandle {
    /// Ends the collector at once: its stream is dropped without a close
    /// marker, or without waiting further for its close ACK.
    fn abort(self, how: &str) {
        self.stop.send_replace(true);
        self.token.cancel();
        self.task.abort();
        if !self.task.is_finished() {
            info!(
                "Stopped collector {} for {} {how}",
                self.kind,
                self.path.display()
            );
        }
    }
}

impl CollectorRuntime {
    /// Creates a runtime with no collector and no Giganto connection.
    ///
    /// The Giganto connection is made with `files`, the TLS files of the
    /// manager connection, and subscribes to `reload`.
    #[must_use]
    pub fn new(files: TlsFiles, reload: ReloadSignal) -> Self {
        let (published, _) = watch::channel(None);
        Self {
            files,
            reload,
            retry_interval: Duration::from_secs(INTERVAL),
            config: None,
            connection: None,
            published,
            sequence: 0,
            collectors: HashMap::new(),
            stopping: Vec::new(),
        }
    }

    /// Sets how long the runtime waits between connect attempts, between a
    /// collector's failed stream recoveries, and at least between a
    /// collector's successful ones.
    #[must_use]
    pub fn with_retry_interval(mut self, retry_interval: Duration) -> Self {
        self.retry_interval = retry_interval;
        self
    }

    /// Stops every collector, closing each stream with its close marker, and
    /// closes the Giganto connection.
    ///
    /// Streams get [`CHANNEL_CLOSE_TIMEOUT`] in total from the start of the
    /// call; a collector still stopping then is ended without waiting
    /// further.
    pub async fn shutdown(&mut self) {
        let deadline = Instant::now() + CHANNEL_CLOSE_TIMEOUT;
        for handle in self.stopping.iter().chain(self.collectors.values()) {
            handle.stop.send_replace(true);
        }
        self.stopping
            .extend(self.collectors.drain().map(|(_, handle)| handle));
        if let Some(connection) = &self.connection {
            connection.token.cancel();
        }
        self.finish_stopping(deadline).await;

        if let Some(connection) = self.connection.take() {
            let _ = connection.task.await;
        }
        if let Some(published) = self.published.send_replace(None) {
            published.connection.close().await;
        }
        self.config = None;
    }

    /// Waits until every stopping collector has ended, or until `deadline`,
    /// when those still stopping are ended at once.
    ///
    /// A collector is removed from `stopping` as soon as it is seen ending,
    /// so a call dropped while waiting leaves the rest for a later call.
    async fn finish_stopping(&mut self, deadline: Instant) {
        let stopping = &mut self.stopping;
        let _ = tokio::time::timeout_at(deadline, async {
            while let Some(handle) = stopping.last_mut() {
                let _ = (&mut handle.task).await;
                stopping.pop();
            }
        })
        .await;
        for handle in self.stopping.drain(..) {
            handle.abort("at the close deadline, without waiting further");
        }
    }

    /// Replaces the connection with one to the address `config` names.
    ///
    /// Cancels connecting and reconnecting for the old address, withdraws the
    /// published connection and spawns a task that closes it, after the
    /// previous connection task has ended, before it connects.
    fn change_connection(&mut self, config: &RemoteConfig) {
        let previous = self.connection.take().map(|previous| {
            previous.token.cancel();
            previous.task
        });
        let old = self
            .published
            .send_replace(None)
            .map(|published| published.connection);

        self.sequence += 1;
        let token = CancellationToken::new();
        let task = tokio::spawn(run_connection(ConnectionContext {
            config: ConnectionConfig {
                cert: self.files.cert.to_string_lossy().into_owned(),
                key: self.files.key.to_string_lossy().into_owned(),
                ca_certs: self
                    .files
                    .ca_certs
                    .iter()
                    .map(|path| path.to_string_lossy().into_owned())
                    .collect(),
                server_addr: config.giganto_ingest_srv_addr,
                server_name: config.giganto_name.clone(),
            },
            reload: self.reload.clone(),
            token: token.clone(),
            previous,
            old,
            published: self.published.clone(),
            sequence: self.sequence,
            retry_interval: self.retry_interval,
        }));
        self.connection = Some(ConnectionTask { token, task });
    }

    fn start_collector(&mut self, config: &CollectorConfig) {
        let (stop, stop_receiver) = watch::channel(false);
        let token = CancellationToken::new();
        let collector = CollectorTask {
            kind: config.kind.clone(),
            path: config.path.clone(),
            stop: stop_receiver.clone(),
            sender: RemoteSender {
                kind: config.kind.clone(),
                stop: stop_receiver,
                link: Link {
                    connection: self.published.subscribe(),
                    token: token.clone(),
                    stream: None,
                    min_sequence: 0,
                    sequence: 0,
                },
                retry_interval: self.retry_interval,
                last_recovered: None,
                failing: false,
            },
        };
        info!(
            "Started collector {} for {}",
            config.kind,
            config.path.display()
        );
        let task = tokio::spawn(collector.run());
        self.collectors.insert(
            (config.kind.clone(), config.path.clone()),
            CollectorHandle {
                kind: config.kind.clone(),
                path: config.path.clone(),
                stop,
                token,
                task,
            },
        );
    }
}

#[async_trait]
impl ConfigRuntime for CollectorRuntime {
    async fn apply(&mut self, config: RemoteConfig) {
        if self.config.as_ref() == Some(&config) {
            return;
        }
        let address_changed = self.config.as_ref().is_none_or(|current| {
            current.giganto_ingest_srv_addr != config.giganto_ingest_srv_addr
                || current.giganto_name != config.giganto_name
        });
        let keys = config
            .collectors
            .iter()
            .map(|collector| (collector.kind.clone(), collector.path.clone()))
            .collect::<HashSet<_>>();
        let removed = self
            .collectors
            .keys()
            .filter(|key| !keys.contains(*key))
            .cloned()
            .collect::<Vec<_>>();
        let stopped = removed.len();

        if address_changed {
            self.change_connection(&config);
            for key in removed {
                if let Some(handle) = self.collectors.remove(&key) {
                    handle.abort("without a close marker");
                }
            }
        } else if !removed.is_empty() {
            let deadline = Instant::now() + CHANNEL_CLOSE_TIMEOUT;
            for key in removed {
                if let Some(handle) = self.collectors.remove(&key) {
                    handle.stop.send_replace(true);
                    self.stopping.push(handle);
                }
            }
            self.finish_stopping(deadline).await;
        }

        let mut started = 0;
        for collector in &config.collectors {
            if !self
                .collectors
                .contains_key(&(collector.kind.clone(), collector.path.clone()))
            {
                self.start_collector(collector);
                started += 1;
            }
        }
        if address_changed || started > 0 || stopped > 0 {
            info!(
                "Applied a configuration with {} collectors: {started} started, {stopped} stopped",
                config.collectors.len()
            );
        }
        self.config = Some(config);
    }
}

impl Drop for CollectorRuntime {
    fn drop(&mut self) {
        for handle in self.stopping.iter().chain(self.collectors.values()) {
            handle.token.cancel();
            handle.task.abort();
        }
        if let Some(connection) = &self.connection {
            connection.token.cancel();
            connection.task.abort();
        }
    }
}

struct ConnectionContext {
    config: ConnectionConfig,
    reload: ReloadSignal,
    token: CancellationToken,
    /// The previous connection task, which closes any connection it
    /// completes after its token was cancelled.
    previous: Option<JoinHandle<()>>,
    /// The connection published before this task was started.
    old: Option<GigantoConnection>,
    published: PublishedSender,
    sequence: u64,
    retry_interval: Duration,
}

/// Connects to Giganto, retrying every failure until `token` is cancelled,
/// and publishes the connection.
async fn run_connection(context: ConnectionContext) {
    let ConnectionContext {
        config,
        reload,
        token,
        previous,
        old,
        published,
        sequence,
        retry_interval,
    } = context;
    // Giganto never sees the new connection before the old one's close.
    if let Some(previous) = previous {
        let _ = previous.await;
    }
    if let Some(old) = old {
        old.close().await;
    }

    info!(
        "Connecting to Giganto at {} as {}",
        config.server_addr, config.server_name
    );
    loop {
        if token.is_cancelled() {
            return;
        }
        match GigantoConnection::connect(
            config.clone(),
            StreamErrorPolicy::ReopenStream,
            &reload,
            token.clone(),
        )
        .await
        {
            Ok(connection) => {
                let mut connection = Some(connection);
                // Checked under the channel's lock, so a connection is never
                // published after the runtime cancelled it and withdrew the
                // published one.
                published.send_if_modified(|current| {
                    if token.is_cancelled() {
                        return false;
                    }
                    *current = connection.take().map(|connection| Published {
                        sequence,
                        connection,
                    });
                    true
                });
                if let Some(connection) = connection {
                    connection.close().await;
                }
                return;
            }
            Err(_) if token.is_cancelled() => return,
            Err(error) => {
                warn!(
                    "Cannot connect to Giganto at {} as {}, retrying in {retry_interval:?}: {}",
                    config.server_addr,
                    config.server_name,
                    chain(&error)
                );
                tokio::select! {
                    () = tokio::time::sleep(retry_interval) => {}
                    () = token.cancelled() => return,
                }
            }
        }
    }
}

/// Why a collector is not reading its file.
#[derive(Debug)]
enum Problem {
    Missing,
    NotRegularFile,
    Stat(io::Error),
    Open(String),
    Read(String),
    Ended(String),
}

impl Problem {
    /// Tells whether two problems are the same state, whatever their
    /// details.
    fn same_as(&self, other: &Self) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }

    fn reason(&self) -> String {
        match self {
            Self::Missing => "the path does not exist".to_string(),
            Self::NotRegularFile => "the path is not a regular file".to_string(),
            Self::Stat(error) => format!("cannot inspect the path: {error}"),
            Self::Open(error) => format!("cannot open the file: {error}"),
            Self::Read(error) => format!("cannot read the file: {error}"),
            Self::Ended(error) => format!("sending ended: {error}"),
        }
    }
}

/// The task of one collector.
struct CollectorTask {
    kind: String,
    path: PathBuf,
    stop: watch::Receiver<bool>,
    sender: RemoteSender,
}

impl CollectorTask {
    async fn run(mut self) {
        // `None` while reading, or before the first attempt.
        let mut problem: Option<Problem> = None;
        loop {
            if *self.stop.borrow() {
                break;
            }
            let found = match self.open_file() {
                Ok(mut collector) => {
                    info!("Reading {} for {}", self.path.display(), self.kind);
                    problem = None;
                    if !self.sender.is_open() && self.sender.open().await.is_err() {
                        break;
                    }
                    let result = run_pipeline_with_sender(
                        &mut self.sender,
                        &mut collector,
                        self.stop.clone(),
                        &mut |_| {},
                    )
                    .await;
                    drop(collector);
                    if *self.stop.borrow() {
                        break;
                    }
                    match result {
                        Err(PipelineError::Collect(error)) => Problem::Read(format!("{error:#}")),
                        Err(error) => Problem::Ended(chain(&error)),
                        Ok(()) => Problem::Ended("the reader ended".to_string()),
                    }
                }
                Err(found) => found,
            };
            if problem
                .as_ref()
                .is_none_or(|problem| !problem.same_as(&found))
            {
                warn!(
                    "Collector {} for {}: {}; retrying every {POLLING_INTERVAL:?}",
                    self.kind,
                    self.path.display(),
                    found.reason()
                );
            }
            problem = Some(found);
            if wait_or_stop(&mut self.stop, POLLING_INTERVAL).await {
                break;
            }
        }

        match self.sender.close().await {
            Ok(CloseAck::NotSent) => info!(
                "Stopped collector {} for {} without a close marker",
                self.kind,
                self.path.display()
            ),
            Ok(close_ack) => info!(
                "Stopped collector {} for {} with close ACK {close_ack:?}",
                self.kind,
                self.path.display()
            ),
            Err(error) => info!(
                "Stopped collector {} for {} without a close marker: {}",
                self.kind,
                self.path.display(),
                chain(&error)
            ),
        }
    }

    /// Opens the file if the path, following symlinks, is a regular file.
    fn open_file(&self) -> Result<LogCollector, Problem> {
        match std::fs::metadata(&self.path) {
            Ok(metadata) if metadata.is_file() => {}
            Ok(_) => return Err(Problem::NotRegularFile),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(Problem::Missing);
            }
            Err(error) => return Err(Problem::Stat(error)),
        }
        LogCollector::new(
            &self.path,
            self.kind.clone(),
            0,
            0,
            true,
            false,
            self.stop.clone(),
        )
        .map_err(|error| Problem::Open(format!("{error:#}")))
    }
}

/// Returns `true` if `stop` is set within `duration`.
async fn wait_or_stop(stop: &mut watch::Receiver<bool>, duration: Duration) -> bool {
    tokio::select! {
        () = tokio::time::sleep(duration) => *stop.borrow(),
        () = stopped(stop) => true,
    }
}

/// Resolves once `stop` is set, or its sender is dropped.
async fn stopped(stop: &mut watch::Receiver<bool>) {
    let _ = stop.wait_for(|&stop| stop).await;
}

/// The sender of one collector: a stream on the published connection that
/// follows the connection across address changes.
struct RemoteSender {
    kind: String,
    stop: watch::Receiver<bool>,
    link: Link,
    retry_interval: Duration,
    /// When the last stream recovery returned successfully.
    last_recovered: Option<Instant>,
    /// Whether sending has failed since the collector last sent.
    failing: bool,
}

/// The stream of one collector and the connection it is opened on.
struct Link {
    connection: PublishedReceiver,
    token: CancellationToken,
    stream: Option<GigantoStream>,
    /// The lowest sequence number of a connection the next stream may be
    /// opened on.
    min_sequence: u64,
    /// The sequence number of the connection `stream` was opened on.
    sequence: u64,
}

impl Link {
    /// Recovers the stream, or opens one when there is none.
    ///
    /// When the runtime closed or cancelled the stream's connection, drops
    /// the stream, so the next attempt opens one on a newer connection.
    async fn attempt(&mut self) -> Result<ReconnectOutcome, SenderError> {
        let result = match &mut self.stream {
            Some(stream) => stream.recover().await,
            None => self.open().await,
        };
        if let Err(error) = &result
            && matches!(error.root(), SenderError::Closed | SenderError::Cancelled)
        {
            self.stream = None;
            self.min_sequence = self.min_sequence.max(self.sequence + 1);
        }
        result
    }

    async fn open(&mut self) -> Result<ReconnectOutcome, SenderError> {
        let published = self.wait_for_connection().await?;
        // Recorded first, so a failure moves on to a newer connection.
        self.sequence = published.sequence;
        let (stream, _) = published
            .connection
            .open_stream(self.token.clone(), AckDelivery::LogOnly)
            .await?;
        self.stream = Some(stream);
        Ok(ReconnectOutcome::Reconnected)
    }

    async fn wait_for_connection(&mut self) -> Result<Published, SenderError> {
        let min_sequence = self.min_sequence;
        let published = self
            .connection
            .wait_for(|published| {
                published
                    .as_ref()
                    .is_some_and(|published| published.sequence >= min_sequence)
            })
            .await
            .map_err(|_| SenderError::Cancelled)?
            .clone();
        published.ok_or(SenderError::Cancelled)
    }
}

impl RemoteSender {
    fn is_open(&self) -> bool {
        self.link.stream.is_some()
    }

    /// Waits for the connection and opens the stream.
    ///
    /// # Errors
    ///
    /// Returns [`SenderError::Cancelled`] once the collector is stopped.
    async fn open(&mut self) -> Result<ReconnectOutcome, SenderError> {
        loop {
            if *self.stop.borrow() {
                return Err(SenderError::Cancelled);
            }
            let result = tokio::select! {
                result = self.link.attempt() => result,
                () = stopped(&mut self.stop) => return Err(SenderError::Cancelled),
            };
            let error = match result {
                Ok(outcome) => return Ok(outcome),
                // The stop and the cancellation `shutdown` follows it with
                // can be ready at once; a stop is not a sending failure.
                Err(_) if *self.stop.borrow() => return Err(SenderError::Cancelled),
                Err(error) => error,
            };
            self.note_failure(&error);
            if matches!(error.root(), SenderError::Closed | SenderError::Cancelled) {
                // The runtime replaced the connection; the next attempt waits
                // for the new one.
                continue;
            }
            if wait_or_stop(&mut self.stop, self.retry_interval).await {
                return Err(SenderError::Cancelled);
            }
        }
    }

    /// Closes the stream with its close marker, if one is open.
    async fn close(&mut self) -> Result<CloseAck, SenderError> {
        match &mut self.link.stream {
            Some(stream) => stream.close().await,
            None => Ok(CloseAck::NotSent),
        }
    }

    fn note_failure(&mut self, error: &dyn StdError) {
        if self.failing {
            debug!("Sending still fails for {}: {}", self.kind, chain(error));
        } else {
            warn!("Sending failed for {}: {}", self.kind, chain(error));
            self.failing = true;
        }
    }

    fn note_sent(&mut self) {
        if self.failing {
            info!("Sending again for {}", self.kind);
            self.failing = false;
        }
    }

    fn stream(&mut self) -> Result<&mut GigantoStream, SendError> {
        self.link
            .stream
            .as_mut()
            .ok_or(SendError::WriteError(WriteError::ClosedStream))
    }
}

#[async_trait]
impl PipelineSender for RemoteSender {
    async fn send_header(&mut self, protocol: RawEventKind) -> Result<(), SenderError> {
        let result = match self.stream() {
            Ok(stream) => stream.send_header(protocol).await,
            Err(error) => Err(SenderError::Send(error)),
        };
        match &result {
            Ok(()) => self.note_sent(),
            Err(error) => self.note_failure(error),
        }
        result
    }

    async fn send_batch(&mut self, events: &[(i64, Vec<u8>)]) -> Result<(), SendError> {
        let result = match self.stream() {
            Ok(stream) => stream.send_batch(events).await,
            Err(error) => Err(error),
        };
        match &result {
            Ok(()) => self.note_sent(),
            Err(error) => self.note_failure(error),
        }
        result
    }

    async fn reconnect(&mut self) -> Result<ReconnectOutcome, SenderError> {
        // A stream that fails again right after every recovery is recovered
        // once per retry interval, not at network round-trip pace.
        if let Some(last_recovered) = self.last_recovered {
            tokio::select! {
                () = tokio::time::sleep_until(last_recovered + self.retry_interval) => {}
                () = stopped(&mut self.stop) => return Err(SenderError::Cancelled),
            }
        }
        let outcome = self.open().await?;
        self.last_recovered = Some(Instant::now());
        Ok(outcome)
    }
}

/// Formats an error with its chain of sources.
fn chain(error: &dyn StdError) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(error) = source {
        let _ = write!(text, ": {error}");
        source = error.source();
    }
    text
}
