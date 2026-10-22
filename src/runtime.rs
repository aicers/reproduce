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
//! Each collector follows its file on a reader thread of its own, turns
//! Giganto's ACKs into an acknowledged position, the position just past the
//! last line Giganto acknowledged, saves it in the state directory as its
//! checkpoint, and resumes reading from it whenever its stream is replaced.

mod acks;
mod checkpoints;
mod follow;

use std::collections::{HashMap, HashSet};
use std::error::Error as StdError;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use giganto_client::{RawEventKind, frame::SendError, ingest::log::Log};
use quinn::WriteError;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use self::acks::Acks;
use self::checkpoints::{Loaded, Saves};
use self::follow::{
    Command, Event, Hook, Initial, LogPosition, Output, Problem, ReaderLink, RefusedDir,
};
use crate::collector::POLLING_INTERVAL;
use crate::config::remote::{CollectorConfig, RESERVED_DIRS, RemoteConfig};
use crate::controller::log_reconnect_outcome;
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
    /// The directories no collector reads a file under.
    refused: Arc<[RefusedDir]>,
    /// Called before the readers' file-system steps, in tests.
    hook: Hook,
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
    /// deleted now. The directories collectors refuse to read under are
    /// inspected now.
    #[must_use]
    pub fn new(files: TlsFiles, reload: ReloadSignal, state_dir: PathBuf) -> Self {
        checkpoints::remove_temporary_files(&state_dir);
        let (published, _) = watch::channel(None);
        Self {
            files,
            reload,
            state_dir,
            file_locks: HashMap::new(),
            refused: follow::refused_dirs(&RESERVED_DIRS).into(),
            hook: Hook::default(),
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
            reader: follow::Settings {
                kind: config.kind.clone(),
                path: config.path.clone(),
                start: config.start,
                poll: POLLING_INTERVAL,
                refused: Arc::clone(&self.refused),
                hook: self.hook.clone(),
            },
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

/// The collector was stopped.
struct Stopped;

/// The task of one collector: the controller of its reader thread. It alone
/// applies the positions the reader reaches, sends the reader's lines and
/// saves starting positions.
struct CollectorTask {
    kind: String,
    path: PathBuf,
    stop: watch::Receiver<bool>,
    state_dir: PathBuf,
    /// What the collector's reader threads read.
    reader: follow::Settings,
    acks: Arc<Acks<LogPosition>>,
    saves: Arc<Saves<LogPosition>>,
    stop_logged: Arc<AtomicBool>,
    /// The task applying the ACKs of the collector's streams.
    drain: JoinHandle<()>,
    sender: RemoteSender,
}

/// When the controller sends the reader its next resume.
#[derive(Clone, Copy, Debug)]
enum Due {
    /// From the acknowledged position, once the stream is ready.
    Acknowledged,
    /// From the controller's current position, no earlier than the instant.
    Current(Instant),
}

/// What a collector's controller keeps between its steps.
#[derive(Default)]
struct Control {
    /// The reader thread, while it runs.
    reader: Option<ReaderLink>,
    /// When to start a reader thread again, while there is none.
    respawn_at: Option<Instant>,
    /// Whether the reader's first `Opened` or `Truncated` was taken.
    started: bool,
    /// Whether the collector has no usable checkpoint, so its first
    /// position is a newly selected starting position.
    needs_start: bool,
    /// A newly selected starting position whose save has not landed, and
    /// when the save is tried again.
    unsaved: Option<(LogPosition, Instant)>,
    /// The number of the last resume sent.
    resume: u64,
    due: Option<Due>,
    /// The version of the acknowledged position last sent to the reader.
    sent_version: Option<u64>,
    /// `None` while reading.
    problem: Option<Problem>,
    stamps: Stamps,
}

impl Control {
    /// The next instant the controller acts at without a result; `open`
    /// tells whether the stream is open, so a due resume can be sent.
    fn deadline(&self, open: bool) -> Instant {
        let mut deadline = Instant::now() + POLLING_INTERVAL;
        for at in [
            self.unsaved.map(|(_, at)| at),
            match self.due {
                Some(Due::Current(at)) if open && self.unsaved.is_none() => Some(at),
                _ => None,
            },
            self.respawn_at.filter(|_| self.reader.is_none()),
        ]
        .into_iter()
        .flatten()
        {
            deadline = deadline.min(at);
        }
        deadline
    }
}

/// Stamps records with strictly increasing timestamps.
#[derive(Debug, Default)]
struct Stamps {
    previous: Option<i64>,
}

impl Stamps {
    /// Returns `max(now, previous + 1)`, in nanoseconds.
    fn next(&mut self, now: i64) -> i64 {
        let stamp = self
            .previous
            .map_or(now, |previous| now.max(previous.saturating_add(1)));
        self.previous = Some(stamp);
        stamp
    }
}

/// Returns the wall clock in nanoseconds.
fn now_nanos() -> i64 {
    i64::try_from(jiff::Timestamp::now().as_nanosecond()).unwrap_or(i64::MAX)
}

impl CollectorTask {
    async fn run(mut self) {
        let mut control = Control::default();
        let _ = self.control(&mut control).await;
        // Drops the reader's channels without waiting for it: a reader that
        // returns later reaches nothing.
        drop(control);

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

    /// Runs the collector until it is stopped.
    async fn control(&mut self, control: &mut Control) -> Result<(), Stopped> {
        loop {
            if *self.stop.borrow() {
                return Err(Stopped);
            }
            if control.reader.is_none() && control.respawn_at.is_none_or(|at| Instant::now() >= at)
            {
                self.spawn_reader(control);
            }
            if let Some((position, at)) = control.unsaved
                && Instant::now() >= at
            {
                control.unsaved = if self.saves.save(&position).await.saved() {
                    None
                } else {
                    Some((position, Instant::now() + POLLING_INTERVAL))
                };
            }
            if control.started && control.unsaved.is_none() && !self.sender.is_open() {
                self.open_stream(control).await?;
            }
            self.send_resume(control);

            let deadline = control.deadline(self.sender.is_open());
            let output = tokio::select! {
                biased;
                () = stopped(&mut self.stop) => return Err(Stopped),
                output = next_result(&mut control.reader) => output,
                () = tokio::time::sleep_until(deadline) => {
                    self.send_acknowledged(control, false);
                    continue;
                }
            };
            match output {
                Some(output) => self.take(control, output).await?,
                None => self.reader_ended(control),
            }
            self.send_acknowledged(control, false);
        }
    }

    /// Starts a reader thread; until the collector has a starting position,
    /// the reader loads the checkpoint and chooses it.
    fn spawn_reader(&mut self, control: &mut Control) {
        let initial = if control.started {
            Initial::Wait
        } else {
            Initial::Load(self.state_dir.clone())
        };
        match follow::spawn(self.reader.clone(), initial, control.resume) {
            Ok(reader) => {
                control.reader = Some(reader);
                control.respawn_at = None;
                control.sent_version = None;
            }
            Err(error) => {
                self.report(control, Problem::Spawn(error.to_string()));
                control.respawn_at = Some(Instant::now() + POLLING_INTERVAL);
            }
        }
    }

    /// The reader thread ended while the collector runs: a new one is
    /// started after [`POLLING_INTERVAL`] and resumed.
    fn reader_ended(&mut self, control: &mut Control) {
        control.reader = None;
        let at = Instant::now() + POLLING_INTERVAL;
        control.respawn_at = Some(at);
        if control.due.is_none() {
            control.due = Some(Due::Current(at));
        }
        self.report(control, Problem::Read("the reader ended".to_string()));
    }

    /// Logs a problem when the collector's state changes.
    fn report(&self, control: &mut Control, problem: Problem) {
        if control
            .problem
            .as_ref()
            .is_none_or(|current| !current.same_as(&problem))
        {
            warn!(
                "Collector {} for {}: {}; retrying every {POLLING_INTERVAL:?}",
                self.kind,
                self.path.display(),
                problem.reason()
            );
        }
        control.problem = Some(problem);
    }

    /// Applies a result of the reader.
    async fn take(&mut self, control: &mut Control, output: Output) -> Result<(), Stopped> {
        if output.resume < control.resume {
            debug!("Dropped a late result of the reader of {}", self.kind);
            return Ok(());
        }
        match output.event {
            Event::Loaded(loaded) => control.needs_start = self.loaded(loaded),
            Event::Opened(position) => {
                control.problem = None;
                if !control.started {
                    control.started = true;
                    if control.needs_start {
                        self.start_at(control, position).await;
                        return Ok(());
                    }
                }
                self.acks.opened(position);
            }
            Event::Batch { lines, end } => self.write(control, lines, end).await?,
            Event::Position(position) => self.acks.consumed(position),
            Event::Truncated(position) => {
                info!(
                    "{} for {} was truncated; reading it again from its beginning",
                    self.path.display(),
                    self.kind
                );
                control.problem = None;
                control.started = true;
                self.start_at(control, position).await;
                // The resume at the new epoch's start is sent once its save
                // lands.
                control.due = Some(Due::Acknowledged);
            }
            Event::Problem(problem) => {
                if matches!(problem, Problem::Read(_)) && control.due.is_none() {
                    control.due = Some(Due::Current(Instant::now() + POLLING_INTERVAL));
                }
                self.report(control, problem);
            }
        }
        Ok(())
    }

    /// Logs the loaded checkpoint and sets the acknowledged position to it.
    /// Returns whether the collector has no usable checkpoint, so its first
    /// position is a newly selected starting position.
    fn loaded(&self, loaded: Loaded) -> bool {
        let file = checkpoints::log_file(&self.state_dir, &self.kind);
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

    /// Sets a newly selected starting position as the acknowledged position
    /// and saves it; a save that does not land is retried every
    /// [`POLLING_INTERVAL`], and nothing is sent until it lands.
    async fn start_at(&mut self, control: &mut Control, position: LogPosition) {
        let outcome = checkpoints::start_at(&self.acks, &self.saves, position).await;
        self.acks.opened(position);
        control.unsaved = (!outcome.saved()).then(|| (position, Instant::now() + POLLING_INTERVAL));
    }

    /// Opens the collector's first stream and sends its record header.
    async fn open_stream(&mut self, control: &mut Control) -> Result<(), Stopped> {
        let outcome = self.sender.open().await.map_err(|_| Stopped)?;
        log_reconnect_outcome(outcome);
        if self.sender.send_header().await.is_err() {
            self.recover(control).await?;
        }
        control.due = Some(Due::Acknowledged);
        Ok(())
    }

    /// Replaces a failed stream: the batch in hand is not sent again, and
    /// the reader resumes from the acknowledged position.
    async fn recover(&mut self, control: &mut Control) -> Result<(), Stopped> {
        loop {
            let outcome = self.sender.reconnect().await.map_err(|_| Stopped)?;
            log_reconnect_outcome(outcome);
            self.acks.dropped();
            if self.sender.send_header().await.is_ok() {
                break;
            }
        }
        control.due = Some(Due::Acknowledged);
        Ok(())
    }

    /// Sends the resume that is due, once the stream is ready and no
    /// starting position is unsaved.
    fn send_resume(&mut self, control: &mut Control) {
        if control.unsaved.is_some() || !self.sender.is_open() || control.reader.is_none() {
            return;
        }
        let position = match control.due {
            Some(Due::Acknowledged) => self.acks.acknowledged(),
            Some(Due::Current(at)) if Instant::now() >= at => {
                self.acks.current().or_else(|| self.acks.acknowledged())
            }
            _ => return,
        };
        control.due = None;
        let Some(position) = position else {
            return;
        };
        control.resume += 1;
        if let Some(reader) = &control.reader {
            reader.send(Command::Resume {
                number: control.resume,
                position,
            });
        }
        self.send_acknowledged(control, true);
    }

    /// Sends the reader the acknowledged position if it changed since it
    /// was last sent, or if `always`.
    fn send_acknowledged(&self, control: &mut Control, always: bool) {
        let Some(reader) = &control.reader else {
            return;
        };
        let (version, position) = self.acks.snapshot();
        if !always && control.sent_version == Some(version) {
            return;
        }
        control.sent_version = Some(version);
        if let Some(position) = position {
            reader.send(Command::Acknowledged(position));
        }
    }

    /// Writes a batch of lines ending just before `end` on the stream.
    async fn write(
        &mut self,
        control: &mut Control,
        lines: Vec<Vec<u8>>,
        end: LogPosition,
    ) -> Result<(), Stopped> {
        if *self.stop.borrow() {
            return Err(Stopped);
        }
        // A batch of a resume sent on this stream is never taken before the
        // stream is ready.
        if control.unsaved.is_some() || control.due.is_some() || !self.sender.is_open() {
            return Ok(());
        }
        let events = lines
            .into_iter()
            .filter_map(|line| {
                let record = bincode::serialize(&Log {
                    kind: self.kind.clone(),
                    log: line,
                })
                .ok()?;
                Some((control.stamps.next(now_nanos()), record))
            })
            .collect::<Vec<_>>();
        if events.is_empty() {
            self.acks.consumed(end);
            return Ok(());
        }
        self.acks.returned(end);
        if self.sender.write(&events).await.is_err() {
            self.recover(control).await?;
        }
        Ok(())
    }
}

/// Resolves to the reader's next result, or `None` once it has ended; never
/// resolves while there is no reader.
async fn next_result(reader: &mut Option<ReaderLink>) -> Option<Output> {
    match reader {
        Some(reader) => reader.results.recv().await,
        None => std::future::pending().await,
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

impl RemoteSender {
    /// Sends the `Log` record header on the stream.
    async fn send_header(&mut self) -> Result<(), SenderError> {
        let result = match self.stream() {
            Ok(stream) => stream.send_header(RawEventKind::Log).await,
            Err(error) => Err(SenderError::Send(error)),
        };
        match &result {
            Ok(()) => self.note_sent(),
            Err(error) => self.note_failure(error),
        }
        result
    }

    /// Writes the batch the reader returned, queueing it for its ACK.
    async fn write(&mut self, events: &[(i64, Vec<u8>)]) -> Result<(), SendError> {
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

    /// Replaces a failed stream.
    ///
    /// # Errors
    ///
    /// Returns [`SenderError::Cancelled`] once the collector is stopped.
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
    use std::io;
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

    #[test]
    fn stamps_strictly_increase() {
        let mut stamps = Stamps::default();
        // A clock that stands still.
        assert_eq!(stamps.next(100), 100);
        assert_eq!(stamps.next(100), 101);
        assert_eq!(stamps.next(100), 102);
        // A clock that steps back.
        assert_eq!(stamps.next(50), 103);
        // A clock that moves on.
        assert_eq!(stamps.next(200), 200);
        // A resume keeps the stamps of the collector: a line read again
        // gets a new, later timestamp.
        let before_resume = stamps.next(200);
        assert_eq!(before_resume, 201);
        assert!(stamps.next(150) > before_resume);
    }

    #[test]
    fn a_stalled_reader_holds_up_nothing() -> anyhow::Result<()> {
        use std::sync::mpsc as std_mpsc;

        use follow::Step;

        use crate::config::remote::{CollectorConfig, CollectorType, StartPosition};

        let state = tempfile::tempdir()?;
        let logs = tempfile::tempdir()?;
        let stalled = logs.path().join("stalled.log");
        std::fs::write(&stalled, b"s1\n")?;
        let other = logs.path().join("other.log");
        std::fs::write(&other, b"o1\n")?;
        // Nothing answers there.
        let silent = std::net::UdpSocket::bind("127.0.0.1:0")?;
        let config = |kind: &str, path: &Path| RemoteConfig {
            giganto_ingest_srv_addr: silent.local_addr().expect("bound"),
            giganto_name: "localhost".to_string(),
            collectors: vec![CollectorConfig {
                collector_type: CollectorType::Log,
                kind: kind.to_string(),
                path: path.to_path_buf(),
                start: StartPosition::Beginning,
            }],
        };

        // The reader of `stalled` blocks in its first open until released.
        let (release, released) = std_mpsc::channel::<()>();
        let released = Mutex::new(released);
        let (entered, entering) = std_mpsc::channel::<()>();
        let entered = Mutex::new(entered);
        let target = stalled.clone();
        let hook = Hook {
            before: Some(Arc::new(move |step, path: &Path| {
                if step == Step::Open && path == target {
                    let _ = entered.lock().expect("lock").send(());
                    let _ = released.lock().expect("lock").recv();
                }
            })),
        };

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let files = TlsFiles {
            cert: state.path().join("cert.pem"),
            key: state.path().join("key.pem"),
            ca_certs: Vec::new(),
        };
        let mut collectors = CollectorRuntime::new(files, ReloadSignal::new(), state.path().into())
            .with_retry_interval(Duration::from_millis(200));
        collectors.hook = hook;
        runtime.block_on(async {
            collectors.apply(config("kind_s", &stalled)).await;
            tokio::task::spawn_blocking(move || entering.recv_timeout(Duration::from_secs(10)))
                .await
                .expect("joined")
                .expect("the reader stalls in its open");

            // Removing the stalled collector and starting another returns at
            // once.
            let started = Instant::now();
            collectors.apply(config("kind_o", &other)).await;
            assert!(
                started.elapsed() < Duration::from_secs(1),
                "{:?}",
                started.elapsed()
            );

            let started = Instant::now();
            collectors.shutdown().await;
            assert!(
                started.elapsed() < CHANNEL_CLOSE_TIMEOUT + Duration::from_secs(2),
                "{:?}",
                started.elapsed()
            );
        });
        drop(collectors);
        let started = std::time::Instant::now();
        drop(runtime);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "{:?}",
            started.elapsed()
        );

        // The released open's late result saves nothing.
        release.send(())?;
        std::thread::sleep(Duration::from_millis(500));
        assert!(!checkpoints::log_file(state.path(), "kind_s").exists());
        Ok(())
    }
}
