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
//!
//! Each collector turns Giganto's ACKs into an acknowledged position, the
//! position just past the last line Giganto acknowledged, and saves it in
//! the state directory as its checkpoint.

mod acks;
mod checkpoints;

use std::collections::{HashMap, HashSet};
use std::error::Error as StdError;
use std::fmt::Write as _;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use giganto_client::{RawEventKind, frame::SendError};
use quinn::WriteError;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use self::acks::Acks;
use self::checkpoints::{Loaded, Saves};
use crate::collector::POLLING_INTERVAL;
use crate::collector::log::{LogCollector, LogPosition, PositionReport};
use crate::config::remote::{CollectorConfig, RemoteConfig};
use crate::controller::{PipelineError, PipelineSender, run_pipeline_with_sender};
use crate::manager::{ConfigRuntime, TlsFiles};
use crate::reload::ReloadSignal;
use crate::sender::{
    AckDelivery, AckReceiver, CHANNEL_CLOSE_TIMEOUT, CloseAck, ConnectionConfig, GigantoConnection,
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
    /// The state directory, which holds the checkpoints.
    state_dir: PathBuf,
    /// The lock every collector of a kind holds while writing its
    /// checkpoint file.
    file_locks: HashMap<String, Arc<Mutex<()>>>,
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
    /// Set by whichever logs the collector's stop line first, the collector
    /// or [`abort`](Self::abort).
    stop_logged: Arc<AtomicBool>,
    acks: Arc<Acks<LogPosition>>,
    saves: Arc<Saves<LogPosition>>,
    /// The task making the collector's periodic saves.
    saver: JoinHandle<()>,
}

impl CollectorHandle {
    /// Ends the collector at once: its stream is dropped without a close
    /// marker, or without waiting further for its close ACK.
    fn abort(self, how: &str) {
        self.stop.send_replace(true);
        self.token.cancel();
        self.task.abort();
        self.log_stopped(how);
    }

    /// Logs the collector's stop line, unless the collector has logged its
    /// own. Returns whether it logged.
    fn log_stopped(&self, how: &str) -> bool {
        if self.stop_logged.swap(true, Ordering::SeqCst) {
            return false;
        }
        info!(
            "Stopped collector {} for {} {how}",
            self.kind,
            self.path.display()
        );
        true
    }
}

impl Drop for CollectorHandle {
    fn drop(&mut self) {
        self.saver.abort();
    }
}

impl CollectorRuntime {
    /// Creates a runtime with no collector and no Giganto connection.
    ///
    /// The Giganto connection is made with `files`, the TLS files of the
    /// manager connection, and subscribes to `reload`. Checkpoints are kept
    /// in `state_dir`; temporary files an interrupted save left there are
    /// deleted now.
    #[must_use]
    pub fn new(files: TlsFiles, reload: ReloadSignal, state_dir: PathBuf) -> Self {
        checkpoints::remove_temporary_files(&state_dir);
        let (published, _) = watch::channel(None);
        Self {
            files,
            reload,
            state_dir,
            file_locks: HashMap::new(),
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

    /// Stops every collector, closing each stream with its close marker,
    /// saves the checkpoint of each, and closes the Giganto connection.
    ///
    /// Streams get [`CHANNEL_CLOSE_TIMEOUT`] in total from the start of the
    /// call; a collector still stopping then is ended without waiting
    /// further. A collector an apply removed is not saved.
    pub async fn shutdown(&mut self) {
        let deadline = Instant::now() + CHANNEL_CLOSE_TIMEOUT;
        for handle in self.stopping.iter().chain(self.collectors.values()) {
            handle.stop.send_replace(true);
        }
        let finals = self
            .collectors
            .values()
            .map(|handle| (Arc::clone(&handle.acks), Arc::clone(&handle.saves)))
            .collect::<Vec<_>>();
        self.stopping
            .extend(self.collectors.drain().map(|(_, handle)| handle));
        if let Some(connection) = &self.connection {
            connection.token.cancel();
        }
        self.finish_stopping(deadline).await;
        for (acks, saves) in finals {
            saves.final_save(acks.acknowledged().as_ref()).await;
        }

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
        let acks = Arc::new(Acks::new());
        let lock = Arc::clone(self.file_locks.entry(config.kind.clone()).or_default());
        let saves = Arc::new(Saves::log(
            &self.state_dir,
            &config.kind,
            &config.path,
            lock,
        ));
        let (receivers, receiver_queue) = mpsc::unbounded_channel();
        let stop_logged = Arc::new(AtomicBool::new(false));
        let collector = CollectorTask {
            kind: config.kind.clone(),
            path: config.path.clone(),
            stop: stop_receiver.clone(),
            state_dir: self.state_dir.clone(),
            acks: Arc::clone(&acks),
            saves: Arc::clone(&saves),
            stop_logged: Arc::clone(&stop_logged),
            drain: tokio::spawn(drain_acks(Arc::clone(&acks), receiver_queue)),
            sender: RemoteSender {
                kind: config.kind.clone(),
                stop: stop_receiver,
                acks: Arc::clone(&acks),
                receivers,
                link: Link {
                    connection: self.published.subscribe(),
                    token: token.clone(),
                    stream: None,
                    receiver: None,
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
        let periodic = tokio::spawn(checkpoints::run_saver(
            Arc::clone(&acks),
            Arc::clone(&saves),
        ));
        self.collectors.insert(
            (config.kind.clone(), config.path.clone()),
            CollectorHandle {
                kind: config.kind.clone(),
                path: config.path.clone(),
                stop,
                token,
                task,
                stop_logged,
                acks,
                saves,
                saver: periodic,
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

        // A removed collector is never saved again, so it cannot overwrite
        // the checkpoint of a new collector of its kind.
        let mut retired = Vec::new();
        if address_changed {
            self.change_connection(&config);
            for key in removed {
                if let Some(handle) = self.collectors.remove(&key) {
                    handle.saves.retire();
                    retired.push(Arc::clone(&handle.saves));
                    handle.abort("without a close marker");
                }
            }
            for saves in retired {
                saves.settle().await;
            }
        } else if !removed.is_empty() {
            let deadline = Instant::now() + CHANNEL_CLOSE_TIMEOUT;
            for key in removed {
                if let Some(handle) = self.collectors.remove(&key) {
                    handle.stop.send_replace(true);
                    handle.saves.retire();
                    retired.push(Arc::clone(&handle.saves));
                    self.stopping.push(handle);
                }
            }
            for saves in retired {
                saves.settle().await;
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
        let changed = address_changed || started > 0 || stopped > 0;
        if changed {
            info!(
                "Applied a configuration with {} collectors: {started} started, {stopped} stopped",
                config.collectors.len()
            );
        }
        let kinds = config
            .collectors
            .iter()
            .map(|collector| collector.kind.clone())
            .collect::<HashSet<_>>();
        self.config = Some(config);

        if changed {
            let state_dir = self.state_dir.clone();
            if let Ok(deletions) = tokio::task::spawn_blocking(move || {
                checkpoints::delete_unconfigured(&state_dir, &kinds)
            })
            .await
            {
                for deletion in deletions {
                    deletion.log();
                }
            }
        }
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
    state_dir: PathBuf,
    acks: Arc<Acks<LogPosition>>,
    saves: Arc<Saves<LogPosition>>,
    stop_logged: Arc<AtomicBool>,
    /// The task applying the ACKs of the collector's streams.
    drain: JoinHandle<()>,
    sender: RemoteSender,
}

impl CollectorTask {
    async fn run(mut self) {
        let mut needs_start = self.load_checkpoint().await;
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
                    if std::mem::take(&mut needs_start) && !self.save_start().await {
                        break;
                    }
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

        let close = self.sender.close().await;
        if !self.stop_logged.swap(true, Ordering::SeqCst) {
            info!(
                "Stopped collector {} for {} {}",
                self.kind,
                self.path.display(),
                stop_outcome(&close)
            );
        }
        // Dropping the stream ends its ACK receiver once every ACK it
        // received is applied.
        let Self { sender, drain, .. } = self;
        drop(sender);
        let _ = drain.await;
    }

    /// Loads the checkpoint into the acknowledged position. Returns whether
    /// the collector has no usable checkpoint, so its first open of the file
    /// sets the starting position.
    async fn load_checkpoint(&self) -> bool {
        let file = checkpoints::log_file(&self.state_dir, &self.kind);
        let loaded = {
            let (state_dir, kind, path) =
                (self.state_dir.clone(), self.kind.clone(), self.path.clone());
            tokio::task::spawn_blocking(move || checkpoints::load_log(&state_dir, &kind, &path))
                .await
                .unwrap_or_else(|error| Loaded::Corrupt {
                    reason: format!("cannot be read ({error})"),
                    end: None,
                })
        };
        let (position, needs_start) = match loaded {
            Loaded::Found(position) => (Some(position), false),
            Loaded::Missing => (None, true),
            Loaded::OtherPath(recorded) => {
                info!(
                    "Checkpoint {} is for {recorded}, not {}; it will be replaced",
                    file.display(),
                    self.path.display()
                );
                (None, true)
            }
            Loaded::Corrupt {
                reason,
                end: Some(end),
            } => {
                warn!(
                    "Checkpoint {} is unusable: {reason}; using the end of {} instead",
                    file.display(),
                    self.path.display()
                );
                (Some(end), true)
            }
            Loaded::Corrupt { reason, end: None } => {
                warn!(
                    "Checkpoint {} is unusable: {reason}; {} cannot be inspected, so {} has no \
                     checkpoint",
                    file.display(),
                    self.path.display(),
                    self.kind
                );
                (None, true)
            }
        };
        self.acks.load(position);
        needs_start
    }

    /// Sets the reader's starting position as the acknowledged position and
    /// saves it durably, retrying every [`POLLING_INTERVAL`] until it lands.
    /// Returns `false` if the collector is stopped first.
    async fn save_start(&mut self) -> bool {
        let Some(start) = self.acks.current() else {
            return true;
        };
        let mut outcome = checkpoints::start_at(&self.acks, &self.saves, start).await;
        while !outcome.saved() {
            if wait_or_stop(&mut self.stop, POLLING_INTERVAL).await {
                return false;
            }
            outcome = self.saves.save(&start).await;
        }
        true
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
        .and_then(|collector| {
            collector.with_position_report(Arc::clone(&self.acks) as Arc<dyn PositionReport>)
        })
        .map_err(|error| Problem::Open(format!("{error:#}")))
    }
}

/// Describes how a collector's stream ended, from the result of its close,
/// for the collector's stop line.
fn stop_outcome(close: &Result<CloseAck, SenderError>) -> String {
    match close {
        Ok(CloseAck::NotSent) => "without a close marker".to_string(),
        Ok(close_ack) => format!("with close ACK {close_ack:?}"),
        Err(error @ SenderError::FinishStream { close_ack, .. })
            if *close_ack != CloseAck::NotSent =>
        {
            format!(
                "after its close marker ({close_ack:?}), but finishing the stream failed: {}",
                chain(error)
            )
        }
        Err(error) => format!("without a close marker: {}", chain(error)),
    }
}

impl PositionReport for Acks<LogPosition> {
    fn opened(&self, position: LogPosition) {
        Acks::opened(self, position);
    }

    fn consumed(&self, position: LogPosition) {
        Acks::consumed(self, position);
    }

    fn returned(&self, position: LogPosition) {
        Acks::returned(self, position);
    }

    fn dropped(&self) {
        Acks::dropped(self);
    }
}

/// Applies the ACKs of a collector's streams as they arrive, from the
/// receivers its sender hands over with the generation that identifies
/// each. Ends once the sender is dropped and the last receiver has ended.
async fn drain_acks(
    acks: Arc<Acks<LogPosition>>,
    mut receivers: mpsc::UnboundedReceiver<(u64, AckReceiver)>,
) {
    enum Event {
        Receiver(Option<(u64, AckReceiver)>),
        Replaced,
        Ack(Option<i64>),
    }

    let mut current: Option<(u64, AckReceiver)> = None;
    let mut sender_open = true;
    loop {
        // Read before waiting, so an ACK received before a replacement and
        // applied after it is discarded; the wait restarts at every
        // replacement, so the new stream's ACKs are not.
        let generation = acks.generation();
        let event = match &mut current {
            None if !sender_open => return,
            None => Event::Receiver(receivers.recv().await),
            Some((_, receiver)) => tokio::select! {
                biased;
                next = receivers.recv(), if sender_open => Event::Receiver(next),
                () = acks.replaced() => Event::Replaced,
                ack = receiver.recv() => Event::Ack(ack),
            },
        };
        match event {
            // A replaced receiver is dropped, never drained further.
            Event::Receiver(Some(next)) => current = Some(next),
            Event::Receiver(None) => sender_open = false,
            // Waits again, from the new generation.
            Event::Replaced => {}
            Event::Ack(Some(timestamp)) => {
                if let Some((receiver, _)) = &current {
                    acks.apply(timestamp, generation, *receiver);
                }
            }
            Event::Ack(None) => current = None,
        }
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
    acks: Arc<Acks<LogPosition>>,
    /// Hands each new ACK receiver to the collector's ACK task.
    receivers: mpsc::UnboundedSender<(u64, AckReceiver)>,
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
    /// The ACK receiver of a stream `open` opened, until it is handed over.
    receiver: Option<AckReceiver>,
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
        let (stream, receiver) = published
            .connection
            .open_stream(self.token.clone(), AckDelivery::Deliver)
            .await?;
        self.stream = Some(stream);
        self.receiver = receiver;
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
                Ok(outcome) => {
                    self.replaced();
                    return Ok(outcome);
                }
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

    /// A new stream is in place: the entries of the replaced one are
    /// dropped, and a new ACK receiver is handed over.
    fn replaced(&mut self) {
        let receiver = self.link.receiver.take();
        let generation = self.acks.replace(receiver.is_some());
        if let Some(receiver) = receiver {
            let _ = self.receivers.send((generation, receiver));
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
        // Queued before the write, so an ACK arriving as soon as it
        // completes finds the entry.
        let entry = events
            .last()
            .and_then(|(timestamp, _)| self.acks.queue(*timestamp));
        let result = match self.stream() {
            Ok(stream) => stream.send_batch(events).await,
            Err(error) => Err(error),
        };
        match &result {
            Ok(()) => {
                self.acks.sent();
                self.note_sent();
            }
            Err(error) => {
                if let Some(entry) = entry {
                    self.acks.failed(entry);
                }
                self.note_failure(error);
            }
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

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    /// Returns what `f` logs.
    fn logged(f: impl FnOnce()) -> String {
        #[derive(Clone, Default)]
        struct Buffer(Arc<Mutex<Vec<u8>>>);

        impl io::Write for Buffer {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.0.lock().expect("lock").extend_from_slice(buf);
                Ok(buf.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let buffer = Buffer::default();
        let writer = buffer.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, f);
        let text = buffer.0.lock().expect("lock").clone();
        String::from_utf8_lossy(&text).into_owned()
    }

    fn handle(task: JoinHandle<()>) -> CollectorHandle {
        let (stop, _) = watch::channel(false);
        CollectorHandle {
            kind: "kind_a".to_string(),
            path: PathBuf::from("/a.log"),
            stop,
            token: CancellationToken::new(),
            task,
            stop_logged: Arc::default(),
            acks: Arc::new(Acks::new()),
            saves: Arc::new(Saves::log(
                Path::new("/nonexistent"),
                "kind_a",
                Path::new("/a.log"),
                Arc::default(),
            )),
            saver: tokio::spawn(async {}),
        }
    }

    #[test]
    fn new_removes_stray_temporary_files() -> anyhow::Result<()> {
        let state = tempfile::tempdir()?;
        let checkpoints = state.path().join("checkpoints");
        let log = checkpoints.join("log");
        std::fs::create_dir_all(&log)?;
        std::fs::write(checkpoints.join("journal.json.tmp"), b"x")?;
        std::fs::write(log.join("kind_a.json.tmp"), b"x")?;
        std::fs::write(log.join("kind_a.json"), b"x")?;
        let files = TlsFiles {
            cert: state.path().join("cert.pem"),
            key: state.path().join("key.pem"),
            ca_certs: Vec::new(),
        };

        let _runtime = CollectorRuntime::new(files, ReloadSignal::new(), state.path().into());
        assert!(!checkpoints.join("journal.json.tmp").exists());
        assert!(!log.join("kind_a.json.tmp").exists());
        assert!(log.join("kind_a.json").exists());
        Ok(())
    }

    #[test]
    fn stop_outcomes_say_whether_a_close_marker_was_sent() {
        let finish = |close_ack| {
            Err(SenderError::FinishStream {
                close_ack,
                source: quinn::ClosedStream::default(),
            })
        };
        let cases = [
            (Ok(CloseAck::NotSent), "without a close marker".to_string()),
            (
                Ok(CloseAck::Received),
                "with close ACK Received".to_string(),
            ),
            (
                Err(SenderError::SendFinish),
                "without a close marker: failed to send channel done message".to_string(),
            ),
            (
                finish(CloseAck::NotSent),
                format!(
                    "without a close marker: failed to finish stream: {}",
                    quinn::ClosedStream::default()
                ),
            ),
            (
                finish(CloseAck::Received),
                format!(
                    "after its close marker (Received), but finishing the stream failed: \
                     failed to finish stream: {}",
                    quinn::ClosedStream::default()
                ),
            ),
            (
                finish(CloseAck::TimedOut),
                format!(
                    "after its close marker (TimedOut), but finishing the stream failed: \
                     failed to finish stream: {}",
                    quinn::ClosedStream::default()
                ),
            ),
        ];
        for (close, expected) in cases {
            assert_eq!(stop_outcome(&close), expected, "{close:?}");
        }
    }

    #[tokio::test]
    async fn abort_logs_a_stop_line_even_after_the_task_ended() {
        let mut handle = handle(tokio::spawn(std::future::pending()));
        handle.task.abort();
        // The task has finished cancelling before the abort path decides.
        let _ = (&mut handle.task).await;
        assert!(handle.task.is_finished());
        let text = logged(|| handle.abort("without a close marker"));
        assert_eq!(
            text.matches("Stopped collector kind_a for /a.log without a close marker")
                .count(),
            1,
            "{text}"
        );
    }

    #[tokio::test]
    async fn abort_logs_nothing_after_the_collector_logged() {
        let handle = handle(tokio::spawn(std::future::pending()));
        // The collector's own stop logger won.
        handle.stop_logged.store(true, Ordering::SeqCst);
        let text = logged(|| handle.abort("at the close deadline, without waiting further"));
        assert!(!text.contains("Stopped collector"), "{text}");
    }

    #[tokio::test]
    async fn the_stop_line_is_logged_once() {
        let handle = handle(tokio::spawn(async {}));
        assert!(handle.log_stopped("without a close marker"));
        assert!(!handle.log_stopped("without a close marker"));
    }
}
