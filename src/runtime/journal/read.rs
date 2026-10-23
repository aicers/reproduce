//! The reader of the journal collector.
//!
//! The reader is a task of its own. It checks that the system journal is
//! readable, runs journalctl, reads its output a line at a time, selects
//! and maps the entries, and returns them in batches of serialized `OpLog`
//! records on a bounded channel. While the controller writes and the channel
//! is full, the reader reads nothing, so a slow Giganto holds journalctl
//! back through its pipe.
//!
//! The controller steers the reader with commands: a resume starts reading
//! after a position, discarding everything read and not returned, and a
//! pause stops journalctl until the next resume. Every result carries the
//! number of the last resume the reader got, so the controller can drop what
//! the reader produced before it.
//!
//! The reader handles journalctl's own failures: it stops journalctl, waits
//! the retry interval and starts it again after the last entry it read.
//!
//! The reader compares every entry it parses with the one before it, or
//! with the position it started reading after, and warns when journal
//! entries between them may be missing ([`Gaps`]).

use std::fs::{self, OpenOptions};
use std::io;
use std::path::Path;
use std::process::{ExitStatus, Stdio};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use tokio::process::{Child, ChildStderr, Command as Process};
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Instant, sleep, sleep_until};
use tracing::{error, info, warn};

use super::entry::{self, Entry};
use super::gap::Gaps;
use super::limit::{ByCause, Counted, Every};
use super::lines::{Line, LineReader};
use super::{JournalPosition, Settings};
use crate::runtime::checkpoints::{self, LoadedJournal};

/// The capacity of the result channel.
const CAPACITY: usize = 2;

/// The most records in a batch.
const BATCH_RECORDS: usize = 1000;

/// The most serialized record bytes in a batch.
const BATCH_BYTES: usize = 4 * 1024 * 1024;

/// How long after its first record a batch is returned.
const FLUSH_AFTER: Duration = Duration::from_millis(100);

/// The least time between two warnings about over-long lines.
const SKIP_WARNING_INTERVAL: Duration = Duration::from_secs(60);

/// The least time between two warnings or errors of the same cause.
const REPEAT_INTERVAL: Duration = Duration::from_secs(600);

/// The least time between two lines of journalctl's standard error logged.
const STDERR_INTERVAL: Duration = Duration::from_secs(1);

/// The arguments of every journalctl run.
const COMMON_ARGS: [&str; 4] = [
    "--output=json",
    "--all",
    "--no-pager",
    "--output-fields=MESSAGE,PRIORITY,_SYSTEMD_UNIT,_PID,UNIT,CONTAINER_NAME",
];

/// How a reader starts.
pub(super) enum Initial {
    /// Check access to the system journal, load the checkpoint, read the
    /// journal's tail if the checkpoint is corrupt, and return
    /// [`Event::Ready`].
    Load,
    /// Read nothing before the first resume.
    Wait,
}

/// A result of the reader, and the number of the last resume it follows.
#[derive(Debug)]
pub(super) struct Output {
    pub(super) resume: u64,
    pub(super) event: Event,
}

#[derive(Debug)]
pub(super) enum Event {
    /// The system journal is readable, and the collector starts as the
    /// checkpoint says; the first result.
    Ready(Start),
    /// Records, and the position of entries dropped after the last of them.
    Batch {
        records: Vec<Record>,
        after: Option<JournalPosition>,
    },
    /// The position of entries dropped while no record was pending.
    Position(JournalPosition),
}

/// What the checkpoint says about where to start.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Start {
    Found(JournalPosition),
    Missing,
    /// An unusable checkpoint, and the journal's newest entry, if it has one.
    Corrupt {
        reason: String,
        tail: Option<JournalPosition>,
    },
}

/// The record of one kept entry.
#[derive(Debug)]
pub(super) struct Record {
    /// The position of the entry, with its `__REALTIME_TIMESTAMP`.
    pub(super) position: JournalPosition,
    /// The serialized `OpLog`.
    pub(super) data: Vec<u8>,
}

#[derive(Debug)]
enum Command {
    /// Discards everything read and not returned, and reads after the
    /// position, or from the oldest entry.
    Resume {
        number: u64,
        position: Option<JournalPosition>,
    },
    /// Stops journalctl and reads nothing until the next resume; answered
    /// once journalctl has ended.
    Pause(oneshot::Sender<()>),
}

/// The controller's side of a reader. Dropping it ends the reader.
pub(super) struct ReaderLink {
    pub(super) results: mpsc::Receiver<Output>,
    commands: mpsc::UnboundedSender<Command>,
}

impl ReaderLink {
    /// Has the reader discard what it read and not returned, and read after
    /// `position`, or from the oldest entry if there is none.
    pub(super) fn resume(&self, number: u64, position: Option<JournalPosition>) {
        let _ = self.commands.send(Command::Resume { number, position });
    }

    /// Has the reader stop journalctl, killing and reaping it, and read
    /// nothing until the next resume. Returns once it has, or has ended.
    pub(super) async fn pause(&self) {
        let (reply, replied) = oneshot::channel();
        if self.commands.send(Command::Pause(reply)).is_ok() {
            let _ = replied.await;
        }
    }
}

/// Starts a reader; its results carry `resume` until its first resume.
pub(super) fn spawn(settings: Settings, initial: Initial, resume: u64) -> ReaderLink {
    let (results, receiver) = mpsc::channel(CAPACITY);
    let (commands, command_receiver) = mpsc::unbounded_channel();
    let reader = Reader {
        settings,
        results,
        commands: command_receiver,
        number: resume,
        skips: Counted::new(SKIP_WARNING_INTERVAL),
        failures: ByCause::new(REPEAT_INTERVAL),
        stderr: Arc::new(Mutex::new(Every::new(STDERR_INTERVAL))),
        gaps: Gaps::default(),
    };
    tokio::spawn(reader.run(initial));
    ReaderLink {
        results: receiver,
        commands,
    }
}

/// The controller dropped its side of the reader.
struct Closed;

/// A command that arrived while the reader was busy, or `None` if the
/// controller dropped its side.
type Arrived = Option<Command>;

/// What ends reading after a position.
enum Next {
    Paused,
    Resumed(Option<JournalPosition>),
}

/// What a journalctl run does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// Reads every entry after a cursor, or every entry, and exits.
    CatchUp,
    /// Reads the entries after a cursor, or every entry, and waits for more.
    Follow,
    /// Reads the newest entry and exits.
    Tail,
}

/// Why a journalctl run failed.
#[derive(Debug)]
enum Failure {
    Spawn(io::Error),
    Read(io::Error),
    Wait(io::Error),
    /// journalctl ended in follow, or with a failure status otherwise.
    Exit(Mode, ExitStatus),
    /// A line, of the given length, that is not a JSON object with a
    /// `__CURSOR` string.
    Unparsable(usize),
    /// The newest entry's line is longer than the line limit.
    LongTail,
    /// A pause stopped the tail read.
    Paused,
}

/// What a warning about a failure is repeated by.
#[derive(Debug, PartialEq, Eq)]
enum Cause {
    Spawn(io::ErrorKind),
    Read(io::ErrorKind),
    Wait(io::ErrorKind),
    Exit(Mode, ExitStatus),
    Unparsable,
    LongTail,
}

impl Failure {
    /// Returns the cause and the reason to log, or `None` if there is
    /// nothing to log.
    fn describe(&self, journalctl: &Path) -> Option<(Cause, String)> {
        Some(match self {
            Self::Spawn(error) => (
                Cause::Spawn(error.kind()),
                format!("cannot start {}: {error}", journalctl.display()),
            ),
            Self::Read(error) => (
                Cause::Read(error.kind()),
                format!("cannot read the output of journalctl: {error}"),
            ),
            Self::Wait(error) => (
                Cause::Wait(error.kind()),
                format!("cannot wait for journalctl: {error}"),
            ),
            Self::Exit(mode, status) => (
                Cause::Exit(*mode, *status),
                format!(
                    "journalctl ended with {status} while {}",
                    match mode {
                        Mode::CatchUp => "catching up",
                        Mode::Follow => "following the journal",
                        Mode::Tail => "reading the newest entry",
                    }
                ),
            ),
            Self::Unparsable(len) => (
                Cause::Unparsable,
                format!("journalctl wrote an unparsable line of {len} bytes"),
            ),
            Self::LongTail => (
                Cause::LongTail,
                "the newest journal entry is longer than 1 MiB".to_string(),
            ),
            Self::Paused => return None,
        })
    }
}

/// How a journalctl run ended, before journalctl is stopped.
enum Ended {
    Exited(io::Result<ExitStatus>),
    Failed(Failure),
    Interrupted(Arrived),
}

/// What a journalctl run of a session led to.
enum Ran {
    /// Catch-up read every entry and journalctl exited successfully.
    CaughtUp,
    Failed(Failure),
    Interrupted(Next),
}

/// Reading after one position.
struct Session {
    /// The position reading started after.
    start: Option<JournalPosition>,
    /// The last entry read since, kept or dropped.
    last_read: Option<JournalPosition>,
    /// The lines skipped for their length since the last entry read in the
    /// current journalctl run.
    skipped: u64,
    /// The records not returned yet.
    records: Vec<Record>,
    /// The serialized bytes of `records`.
    bytes: usize,
    /// The position of the entries dropped after the last record, or while
    /// no record was pending, not returned yet.
    dropped: Option<JournalPosition>,
    /// When the records or the dropped position are returned.
    flush_at: Option<Instant>,
}

impl Session {
    fn new(start: Option<JournalPosition>) -> Self {
        Self {
            start,
            last_read: None,
            skipped: 0,
            records: Vec::new(),
            bytes: 0,
            dropped: None,
            flush_at: None,
        }
    }

    /// The arguments of a run in `mode` besides [`COMMON_ARGS`]: after the
    /// last entry read, or after the start position when nothing was read.
    fn args(&self, mode: Mode) -> Vec<String> {
        let mut args = Vec::new();
        if mode == Mode::Follow {
            args.push("--follow".to_string());
            args.push("--lines=all".to_string());
        }
        if let Some(position) = self.predecessor() {
            args.push(format!("--after-cursor={}", position.cursor));
        }
        args
    }

    /// The entry the next entry read follows: the last one read, or the
    /// start position when nothing was read.
    fn predecessor(&self) -> Option<&JournalPosition> {
        self.last_read.as_ref().or(self.start.as_ref())
    }

    fn schedule(&mut self) {
        if self.flush_at.is_none() {
            self.flush_at = Some(Instant::now() + FLUSH_AFTER);
        }
    }
}

struct Reader {
    settings: Settings,
    results: mpsc::Sender<Output>,
    commands: mpsc::UnboundedReceiver<Command>,
    /// The number of the last resume.
    number: u64,
    /// Counts the lines skipped for their length, for their warning.
    skips: Counted,
    /// Limits the warnings about journalctl failures.
    failures: ByCause<Cause>,
    /// Limits the lines of journalctl's standard error logged.
    stderr: Arc<Mutex<Every>>,
    /// The lost-interval check.
    gaps: Gaps,
}

impl Reader {
    async fn run(mut self, initial: Initial) {
        let _ = self.main(initial).await;
    }

    async fn main(&mut self, initial: Initial) -> Result<(), Closed> {
        if let Initial::Load = initial {
            let start = self.prepare().await?;
            // The channel is empty before the first result.
            self.results
                .try_send(Output {
                    resume: self.number,
                    event: Event::Ready(start),
                })
                .map_err(|_| Closed)?;
        }
        let mut next = Next::Paused;
        loop {
            let start = match next {
                Next::Resumed(position) => position,
                Next::Paused => {
                    let arrived = self.commands.recv().await;
                    match self.interrupt(arrived)? {
                        Next::Paused => continue,
                        Next::Resumed(position) => position,
                    }
                }
            };
            next = self.read(start).await?;
        }
    }

    /// Applies a command that arrived while no journalctl runs.
    fn interrupt(&mut self, arrived: Arrived) -> Result<Next, Closed> {
        match arrived {
            None => Err(Closed),
            Some(Command::Pause(reply)) => {
                let _ = reply.send(());
                Ok(Next::Paused)
            }
            Some(Command::Resume { number, position }) => {
                self.number = number;
                Ok(Next::Resumed(position))
            }
        }
    }

    /// Runs `future` before the first result, answering pauses at once.
    async fn prepared<F: Future>(&mut self, future: F) -> Result<F::Output, Closed> {
        tokio::pin!(future);
        loop {
            tokio::select! {
                output = &mut future => return Ok(output),
                command = self.commands.recv() => match command {
                    None => return Err(Closed),
                    Some(Command::Pause(reply)) => {
                        let _ = reply.send(());
                    }
                    // The controller resumes only after the first result.
                    Some(Command::Resume { number, .. }) => self.number = number,
                },
            }
        }
    }

    /// Waits until the system journal is readable, loads the checkpoint, and
    /// reads the journal's tail if the checkpoint is corrupt.
    async fn prepare(&mut self) -> Result<Start, Closed> {
        self.check_access().await?;
        let state_dir = self.settings.state_dir.clone();
        let loaded = self
            .prepared(tokio::task::spawn_blocking(move || {
                checkpoints::load_journal(&state_dir)
            }))
            .await?
            .unwrap_or_else(|error| LoadedJournal::Corrupt(format!("cannot be read ({error})")));
        Ok(match loaded {
            LoadedJournal::Found(position) => Start::Found(position),
            LoadedJournal::Missing => Start::Missing,
            LoadedJournal::Corrupt(reason) => Start::Corrupt {
                reason,
                tail: self.tail().await?,
            },
        })
    }

    /// Checks access to the system journal until it passes, every retry
    /// interval, logging the error at most every [`REPEAT_INTERVAL`].
    async fn check_access(&mut self) -> Result<(), Closed> {
        let mut errors = Every::new(REPEAT_INTERVAL);
        let mut failed = false;
        loop {
            let paths = self.settings.paths.clone();
            let checked = self
                .prepared(tokio::task::spawn_blocking(move || {
                    check_access(&paths.machine_id, &paths.journal_root)
                }))
                .await?
                .unwrap_or_else(|error| Err(error.to_string()));
            match checked {
                Ok(()) => {
                    if failed {
                        info!("Journal collector: the system journal is readable");
                    }
                    return Ok(());
                }
                Err(reason) => {
                    if errors.ready(std::time::Instant::now()) {
                        error!(
                            "Journal collector: cannot read the system journal; is the unit in \
                             group adm? ({reason}); retrying every {:?}",
                            self.settings.retry_interval
                        );
                    }
                    failed = true;
                }
            }
            self.prepared(sleep(self.settings.retry_interval)).await?;
        }
    }

    /// Reads the journal's newest entry, retrying a failure every retry
    /// interval. Returns `None` for an empty journal.
    async fn tail(&mut self) -> Result<Option<JournalPosition>, Closed> {
        loop {
            match self.read_tail().await? {
                Ok(tail) => return Ok(tail),
                Err(failure) => {
                    self.failed(&failure);
                    self.prepared(sleep(self.settings.retry_interval)).await?;
                }
            }
        }
    }

    async fn read_tail(&mut self) -> Result<Result<Option<JournalPosition>, Failure>, Closed> {
        let mut child = match self.spawn(&["--lines=1".to_string()]) {
            Ok(child) => child,
            Err(error) => return Ok(Err(Failure::Spawn(error))),
        };
        let Some(stdout) = child.stdout.take() else {
            stop(&mut child).await;
            return Ok(Err(Failure::Read(io::Error::other("no standard output"))));
        };
        let mut lines = LineReader::new(stdout);
        let mut tail = Ok(None);
        let ended = loop {
            let line = tokio::select! {
                biased;
                command = self.commands.recv() => break Ended::Interrupted(command),
                line = lines.next() => line,
            };
            match line {
                Err(error) => break Ended::Failed(Failure::Read(error)),
                Ok(None) => {
                    break tokio::select! {
                        biased;
                        command = self.commands.recv() => Ended::Interrupted(command),
                        status = child.wait() => Ended::Exited(status),
                    };
                }
                Ok(Some(Line::Skipped)) => tail = Err(Failure::LongTail),
                Ok(Some(Line::Complete(line))) => match entry::parse(&line) {
                    Some(entry) => tail = Ok(Some(entry.position)),
                    None => tail = Err(Failure::Unparsable(line.len())),
                },
            }
        };
        stop(&mut child).await;
        Ok(match ended {
            Ended::Exited(Ok(status)) if status.success() => tail,
            Ended::Exited(Ok(status)) => Err(Failure::Exit(Mode::Tail, status)),
            Ended::Exited(Err(error)) => Err(Failure::Wait(error)),
            Ended::Failed(failure) => Err(failure),
            Ended::Interrupted(None) => return Err(Closed),
            Ended::Interrupted(Some(Command::Pause(reply))) => {
                let _ = reply.send(());
                Err(Failure::Paused)
            }
            Ended::Interrupted(Some(Command::Resume { number, .. })) => {
                self.number = number;
                Err(Failure::Paused)
            }
        })
    }

    /// Reads after `start`, or from the oldest entry, until a command
    /// interrupts: catch-up, then follow. A failed journalctl is started
    /// again after the retry interval, after the last entry read.
    async fn read(&mut self, start: Option<JournalPosition>) -> Result<Next, Closed> {
        let mut session = Session::new(start);
        loop {
            for mode in [Mode::CatchUp, Mode::Follow] {
                match self.run_journalctl(&mut session, mode).await? {
                    Ran::CaughtUp => {}
                    Ran::Interrupted(next) => return Ok(next),
                    Ran::Failed(failure) => {
                        self.failed(&failure);
                        if let Some(next) = self.wait(&mut session).await? {
                            return Ok(next);
                        }
                        break;
                    }
                }
            }
        }
    }

    /// Runs journalctl once in `mode`, and stops it.
    async fn run_journalctl(&mut self, session: &mut Session, mode: Mode) -> Result<Ran, Closed> {
        // The run reads again every line after the last entry read.
        session.skipped = 0;
        let mut child = match self.spawn(&session.args(mode)) {
            Ok(child) => child,
            Err(error) => return Ok(Ran::Failed(Failure::Spawn(error))),
        };
        let ended = match child.stdout.take() {
            Some(stdout) => {
                self.take_output(session, &mut LineReader::new(stdout), &mut child)
                    .await
            }
            None => Ended::Failed(Failure::Read(io::Error::other("no standard output"))),
        };
        stop(&mut child).await;
        Ok(match ended {
            Ended::Exited(Ok(status)) if mode == Mode::CatchUp && status.success() => {
                // Catch-up ends: what it read is returned.
                match self.flush(session).await {
                    Ok(()) => Ran::CaughtUp,
                    Err(arrived) => Ran::Interrupted(self.interrupt(arrived)?),
                }
            }
            Ended::Exited(Ok(status)) => Ran::Failed(Failure::Exit(mode, status)),
            Ended::Exited(Err(error)) => Ran::Failed(Failure::Wait(error)),
            Ended::Failed(failure) => Ran::Failed(failure),
            Ended::Interrupted(arrived) => Ran::Interrupted(self.interrupt(arrived)?),
        })
    }

    /// Takes journalctl's output until it ends or a command interrupts.
    async fn take_output(
        &mut self,
        session: &mut Session,
        lines: &mut LineReader<tokio::process::ChildStdout>,
        child: &mut Child,
    ) -> Ended {
        loop {
            let flush_at = session.flush_at;
            let line = tokio::select! {
                biased;
                command = self.commands.recv() => return Ended::Interrupted(command),
                () = sleep_until(flush_at.unwrap_or_else(Instant::now)), if flush_at.is_some() => {
                    if let Err(arrived) = self.flush(session).await {
                        return Ended::Interrupted(arrived);
                    }
                    continue;
                }
                line = lines.next() => line,
            };
            match line {
                Err(error) => return Ended::Failed(Failure::Read(error)),
                Ok(None) => {
                    return tokio::select! {
                        biased;
                        command = self.commands.recv() => Ended::Interrupted(command),
                        status = child.wait() => Ended::Exited(status),
                    };
                }
                Ok(Some(Line::Skipped)) => {
                    session.skipped = session.skipped.saturating_add(1);
                    if let Some(count) = self.skips.count(std::time::Instant::now()) {
                        warn!(
                            "Journal collector: skipped {count} journal entries whose journalctl \
                             output line is longer than 1 MiB"
                        );
                    }
                }
                Ok(Some(Line::Complete(line))) => {
                    let Some(entry) = entry::parse(&line) else {
                        return Ended::Failed(Failure::Unparsable(line.len()));
                    };
                    if let Some(previous) = session.predecessor() {
                        self.gaps.check(previous, &entry.position, session.skipped);
                    }
                    session.skipped = 0;
                    if let Err(arrived) = self.take(session, entry).await {
                        return Ended::Interrupted(arrived);
                    }
                }
            }
        }
    }

    /// Adds an entry read to the session.
    async fn take(&mut self, session: &mut Session, entry: Entry) -> Result<(), Arrived> {
        session.last_read = Some(entry.position.clone());
        let Some(data) = entry.record else {
            session.dropped = Some(entry.position);
            session.schedule();
            return Ok(());
        };
        if !session.records.is_empty() && session.bytes + data.len() > BATCH_BYTES {
            self.flush(session).await?;
        }
        session.bytes += data.len();
        session.records.push(Record {
            position: entry.position,
            data,
        });
        session.dropped = None;
        session.schedule();
        if session.records.len() >= BATCH_RECORDS {
            self.flush(session).await?;
        }
        Ok(())
    }

    /// Returns the pending records, or the position of the entries dropped
    /// while none was pending.
    async fn flush(&mut self, session: &mut Session) -> Result<(), Arrived> {
        session.flush_at = None;
        let after = session.dropped.take();
        let event = if !session.records.is_empty() {
            session.bytes = 0;
            Event::Batch {
                records: std::mem::take(&mut session.records),
                after,
            }
        } else if let Some(position) = after {
            Event::Position(position)
        } else {
            return Ok(());
        };
        self.deliver(event).await
    }

    /// Returns `event` to the controller once the channel has room, unless
    /// a command arrives first; the event is then dropped.
    async fn deliver(&mut self, event: Event) -> Result<(), Arrived> {
        let output = Output {
            resume: self.number,
            event,
        };
        tokio::select! {
            biased;
            command = self.commands.recv() => Err(command),
            permit = self.results.reserve() => match permit {
                Ok(permit) => {
                    permit.send(output);
                    Ok(())
                }
                Err(_) => Err(None),
            },
        }
    }

    /// Waits the retry interval after a failure, returning the pending
    /// records when due. Returns the command that interrupts the wait.
    async fn wait(&mut self, session: &mut Session) -> Result<Option<Next>, Closed> {
        let until = Instant::now() + self.settings.retry_interval;
        let arrived = loop {
            let flush_at = session.flush_at;
            tokio::select! {
                biased;
                command = self.commands.recv() => break command,
                () = sleep_until(flush_at.unwrap_or(until)), if flush_at.is_some() => {
                    if let Err(arrived) = self.flush(session).await {
                        break arrived;
                    }
                }
                () = sleep_until(until) => return Ok(None),
            }
        };
        self.interrupt(arrived).map(Some)
    }

    /// Logs a failure, at most every [`REPEAT_INTERVAL`] for the same cause.
    fn failed(&mut self, failure: &Failure) {
        let Some((cause, reason)) = failure.describe(&self.settings.paths.journalctl) else {
            return;
        };
        if self.failures.ready(cause, std::time::Instant::now()) {
            warn!(
                "Journal collector: {reason}; starting journalctl again in {:?}",
                self.settings.retry_interval
            );
        }
    }

    /// Starts journalctl with [`COMMON_ARGS`] and `args`, logging its
    /// standard error.
    fn spawn(&self, args: &[String]) -> io::Result<Child> {
        let mut child = Process::new(&self.settings.paths.journalctl)
            .args(COMMON_ARGS)
            .args(args)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        if let Some(stderr) = child.stderr.take() {
            tokio::spawn(log_stderr(stderr, Arc::clone(&self.stderr)));
        }
        Ok(child)
    }
}

/// Kills and reaps journalctl, if it still runs.
async fn stop(child: &mut Child) {
    // An exited and reaped child cannot be killed; there is nothing to do.
    let _ = child.kill().await;
}

/// Logs journalctl's standard error at WARN, at most one line per
/// [`STDERR_INTERVAL`]; lines arriving sooner are discarded.
async fn log_stderr(stderr: ChildStderr, limit: Arc<Mutex<Every>>) {
    let mut lines = LineReader::new(stderr);
    while let Ok(Some(line)) = lines.next().await {
        let ready = limit
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .ready(std::time::Instant::now());
        if !ready {
            continue;
        }
        match line {
            Line::Complete(line) => warn!("journalctl: {}", String::from_utf8_lossy(&line)),
            Line::Skipped => warn!("journalctl wrote an error line longer than 1 MiB"),
        }
    }
}

/// Checks that the system journal can be read: the machine ID in
/// `machine_id` is valid, the journal directory `<journal_root>/<machine ID>`
/// can be listed, and `system.journal` in it, or one `system@*.journal`
/// archive when that is absent, can be opened.
fn check_access(machine_id: &Path, journal_root: &Path) -> Result<(), String> {
    let id = fs::read_to_string(machine_id)
        .map_err(|error| format!("cannot read {}: {error}", machine_id.display()))?;
    let id = id.trim();
    if id.len() != 32
        || !id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(format!(
            "{} does not hold a valid machine ID",
            machine_id.display()
        ));
    }
    let dir = journal_root.join(id);
    let list_error = |error: io::Error| format!("cannot list {}: {error}", dir.display());
    let mut archive = None;
    let mut active = false;
    for entry in fs::read_dir(&dir).map_err(list_error)? {
        let entry = entry.map_err(list_error)?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name == "system.journal" {
            active = true;
            break;
        }
        if archive.is_none() && name.starts_with("system@") && name.ends_with(".journal") {
            archive = Some(name.to_string());
        }
    }
    let file = if active {
        "system.journal".to_string()
    } else {
        archive.ok_or_else(|| format!("{} holds no system journal file", dir.display()))?
    };
    let path = dir.join(file);
    let mut options = OpenOptions::new();
    options.read(true);
    std::os::unix::fs::OpenOptionsExt::custom_flags(
        &mut options,
        libc::O_NONBLOCK | libc::O_NOCTTY,
    );
    options
        .open(&path)
        .map(drop)
        .map_err(|error| format!("cannot open {}: {error}", path.display()))
}
