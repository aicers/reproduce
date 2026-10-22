//! The follow reader of remote-mode log collectors.
//!
//! Each collector reads its file on a thread of its own. The reader opens a
//! file only after checking what it is and where it lies, follows it as it
//! grows and across rename and copy-truncate rotation, and returns its lines
//! in batches on a bounded channel. The collector's controller alone applies
//! the positions the reader reaches, sends the lines and saves checkpoints;
//! it steers the reader with commands on a channel of its own.
//!
//! Every result carries the number of the last [`Command::Resume`] the reader
//! got, so the controller can drop what the reader produced before it.

use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read as _, Seek as _, SeekFrom};
use std::mem::{Discriminant, discriminant};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{self as std_mpsc, RecvTimeoutError, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use super::checkpoints::{self, Loaded};
use crate::config::remote::StartPosition;

/// The most bytes held while a line waits for its `\n`; a longer line is
/// returned in pieces of this size.
const MAX_HELD: usize = 1024 * 1024;

/// The most lines in a batch.
const BATCH_LINES: usize = 1000;

/// The most line bytes in a batch.
const BATCH_BYTES: usize = 4 * 1024 * 1024;

/// The capacity of the result channel.
const CAPACITY: usize = 2;

/// The size of one read.
const CHUNK: usize = 64 * 1024;

/// A position in a log file: the device and inode of the open file, and the
/// byte offset just past the last line handled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct LogPosition {
    pub(super) dev: u64,
    pub(super) ino: u64,
    pub(super) offset: u64,
}

impl LogPosition {
    /// Returns the position `offset` in the file `metadata` describes.
    pub(super) fn new(metadata: &Metadata, offset: u64) -> Self {
        Self::at(Identity::of(metadata), offset)
    }

    fn at(id: Identity, offset: u64) -> Self {
        Self {
            dev: id.dev,
            ino: id.ino,
            offset,
        }
    }

    fn identity(&self) -> Identity {
        Identity {
            dev: self.dev,
            ino: self.ino,
        }
    }
}

/// The device and inode of a file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Identity {
    dev: u64,
    ino: u64,
}

impl Identity {
    fn of(metadata: &Metadata) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Self {
                dev: metadata.dev(),
                ino: metadata.ino(),
            }
        }
        #[cfg(not(unix))]
        {
            let _ = metadata;
            Self { dev: 0, ino: 0 }
        }
    }
}

/// A directory no collector may read a file under, identified by its device
/// and inode.
#[derive(Clone, Debug)]
pub(super) struct RefusedDir {
    id: Identity,
    /// The directory as listed.
    name: String,
}

/// Returns the identities of `dirs`, following symbolic links, skipping
/// those that cannot be inspected.
pub(super) fn refused_dirs<S: AsRef<str>>(dirs: &[S]) -> Vec<RefusedDir> {
    dirs.iter()
        .filter_map(|dir| {
            let name = dir.as_ref();
            let metadata = fs::metadata(name).ok()?;
            Some(RefusedDir {
                id: Identity::of(&metadata),
                name: name.to_string(),
            })
        })
        .collect()
}

/// Why a collector is not reading its file.
#[derive(Debug)]
pub(super) enum Problem {
    Missing,
    NotRegularFile,
    Stat(io::Error),
    Open(String),
    Read(String),
    /// The file lies under the refused directory named.
    Refused(String),
    /// Where the file lies cannot be checked.
    Locate(String),
    /// The reader thread cannot be started.
    Spawn(String),
}

impl Problem {
    /// Tells whether two problems are the same state, whatever their
    /// details.
    pub(super) fn same_as(&self, other: &Self) -> bool {
        discriminant(self) == discriminant(other)
    }

    pub(super) fn reason(&self) -> String {
        match self {
            Self::Missing => "the path does not exist".to_string(),
            Self::NotRegularFile => "the path is not a regular file".to_string(),
            Self::Stat(error) => format!("cannot inspect the path: {error}"),
            Self::Open(error) => format!("cannot open the file: {error}"),
            Self::Read(error) => format!("cannot read the file: {error}"),
            Self::Refused(dir) => format!("the file lies under the refused directory {dir}"),
            Self::Locate(error) => format!("cannot check where the file lies: {error}"),
            Self::Spawn(error) => format!("cannot start the reader: {error}"),
        }
    }
}

/// A file-system step the reader is about to take, for tests to act on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Step {
    /// Loading the checkpoint.
    Load,
    /// Inspecting a path.
    Stat,
    /// Opening a path, after inspecting it.
    Open,
}

/// What a test runs before a reader's file-system step.
#[cfg(test)]
pub(super) type Before = Arc<dyn Fn(Step, &Path) + Send + Sync>;

/// Called before each file-system [`Step`] of the reader; does nothing
/// outside tests.
#[derive(Clone, Default)]
pub(super) struct Hook {
    #[cfg(test)]
    pub(super) before: Option<Before>,
}

impl Hook {
    #[cfg_attr(not(test), allow(clippy::unused_self))]
    fn before(&self, step: Step, path: &Path) {
        #[cfg(test)]
        if let Some(before) = &self.before {
            before(step, path);
        }
        #[cfg(not(test))]
        let _ = (step, path);
    }
}

/// A file that passed the opening checks.
struct Opened {
    file: File,
    id: Identity,
    len: u64,
    /// Where the file lies.
    real_path: PathBuf,
}

/// Opens `path` for reading if it is a regular file that lies under none of
/// `refused`.
///
/// The open never blocks, even on a FIFO or a device swapped in after the
/// path was inspected: such a file is refused once open.
fn open_checked(path: &Path, refused: &[RefusedDir], hook: &Hook) -> Result<Opened, Problem> {
    hook.before(Step::Stat, path);
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => {}
        Ok(_) => return Err(Problem::NotRegularFile),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Err(Problem::Missing),
        Err(error) => return Err(Problem::Stat(error)),
    }
    hook.before(Step::Open, path);
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(
        &mut options,
        libc::O_NONBLOCK | libc::O_NOCTTY,
    );
    let file = options.open(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            Problem::Missing
        } else {
            Problem::Open(error.to_string())
        }
    })?;
    let metadata = file.metadata().map_err(Problem::Stat)?;
    if !metadata.is_file() {
        return Err(Problem::NotRegularFile);
    }
    let id = Identity::of(&metadata);
    let real_path =
        real_path(&file, path, id).map_err(|error| Problem::Locate(error.to_string()))?;
    check_ancestors(&real_path, refused)?;
    Ok(Opened {
        file,
        id,
        len: metadata.len(),
        real_path,
    })
}

/// Returns where the open `file` lies.
#[cfg(target_os = "linux")]
fn real_path(file: &File, _path: &Path, _id: Identity) -> io::Result<PathBuf> {
    use std::os::fd::AsRawFd;

    let real = fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))?;
    absolute(real)
}

/// Returns where the open `file` lies: `path` resolved, if it still names
/// the file.
#[cfg(not(target_os = "linux"))]
fn real_path(_file: &File, path: &Path, id: Identity) -> io::Result<PathBuf> {
    let real = fs::canonicalize(path)?;
    if Identity::of(&fs::metadata(&real)?) != id {
        return Err(io::Error::other(format!(
            "{} no longer names the open file",
            real.display()
        )));
    }
    absolute(real)
}

fn absolute(path: PathBuf) -> io::Result<PathBuf> {
    if path.is_absolute() {
        Ok(path)
    } else {
        Err(io::Error::other(format!(
            "{} is not an absolute path",
            path.display()
        )))
    }
}

/// Refuses `real_path` if any of its ancestors is one of `refused`.
fn check_ancestors(real_path: &Path, refused: &[RefusedDir]) -> Result<(), Problem> {
    for dir in real_path.ancestors().skip(1) {
        let metadata = fs::metadata(dir)
            .map_err(|error| Problem::Locate(format!("{}: {error}", dir.display())))?;
        let id = Identity::of(&metadata);
        if let Some(refused) = refused.iter().find(|refused| refused.id == id) {
            return Err(Problem::Refused(refused.name.clone()));
        }
    }
    Ok(())
}

/// What a reader reads and how.
#[derive(Clone)]
pub(super) struct Settings {
    pub(super) kind: String,
    pub(super) path: PathBuf,
    pub(super) start: StartPosition,
    /// How often the reader checks the file at EOF, and the quiet interval
    /// of a rename rotation.
    pub(super) poll: Duration,
    pub(super) refused: Arc<[RefusedDir]>,
    pub(super) hook: Hook,
}

/// How a reader starts.
pub(super) enum Initial {
    /// Load the checkpoint from the state directory, and open the file and
    /// choose the starting position at once.
    Load(PathBuf),
    /// Open nothing before the first [`Command::Resume`].
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
    /// The outcome of loading the checkpoint; the first result.
    Loaded(Loaded),
    /// The reader opened a file, or repositioned on one, and reads from the
    /// position.
    Opened(LogPosition),
    /// Lines, and the position just past the last of them.
    Batch {
        lines: Vec<Vec<u8>>,
        end: LogPosition,
    },
    /// The reader consumed bytes it returns no line for.
    Position(LogPosition),
    /// The file was truncated: a new content epoch starts at the position,
    /// and the reader waits for a resume there.
    Truncated(LogPosition),
    Problem(Problem),
}

#[derive(Clone, Copy, Debug)]
pub(super) enum Command {
    /// Discards everything read and not returned, and continues from the
    /// position.
    Resume {
        number: u64,
        position: LogPosition,
    },
    /// The acknowledged position.
    Acknowledged(LogPosition),
    Stop,
}

/// The controller's side of a reader thread. Dropping it ends the reader
/// without waiting for it.
pub(super) struct ReaderLink {
    pub(super) results: mpsc::Receiver<Output>,
    commands: std_mpsc::Sender<Command>,
}

impl ReaderLink {
    pub(super) fn send(&self, command: Command) {
        let _ = self.commands.send(command);
    }
}

impl Drop for ReaderLink {
    fn drop(&mut self) {
        let _ = self.commands.send(Command::Stop);
    }
}

/// Starts a reader thread; its results carry `resume` until its first
/// [`Command::Resume`].
///
/// The thread logs to the subscriber of the caller.
///
/// # Errors
///
/// Returns an error if the thread cannot be spawned.
pub(super) fn spawn(settings: Settings, initial: Initial, resume: u64) -> io::Result<ReaderLink> {
    let (results, receiver) = mpsc::channel(CAPACITY);
    let (commands, command_receiver) = std_mpsc::channel();
    let reader = Reader::new(settings, results, command_receiver, resume);
    let dispatch = tracing::dispatcher::get_default(Clone::clone);
    thread::Builder::new()
        .name("reproduce-reader".to_string())
        .spawn(move || {
            tracing::dispatcher::with_default(&dispatch, || reader.run(initial));
        })?;
    Ok(ReaderLink {
        results: receiver,
        commands,
    })
}

/// The results channel or the command channel is closed, or the reader was
/// told to stop.
struct Closed;

/// Whether the reader may read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Gate {
    Open,
    /// Waiting for a resume: before the first, and after a read error.
    Paused,
    /// Waiting for a resume at the start of the truncated file.
    Truncated(Identity),
}

/// What the reader opens when it has no file.
#[derive(Clone, Copy, Debug)]
enum Target {
    /// The starting position of a collector with no checkpoint.
    Start,
    /// `path` from its beginning.
    Zero,
    /// The position, by the rules of resuming.
    Resume(LogPosition),
}

/// An open file.
struct Handle {
    file: File,
    id: Identity,
    /// The offset read to, held bytes included.
    offset: u64,
}

struct Reader {
    settings: Settings,
    results: mpsc::Sender<Output>,
    commands: std_mpsc::Receiver<Command>,
    /// The number of the last resume.
    number: u64,
    gate: Gate,
    /// What to open, while no file is read.
    target: Option<Target>,
    /// The file `path` names, or named when it was opened.
    follow: Option<Handle>,
    /// A predecessor of `follow`: drained if `draining`, or else a
    /// rotated-away file held until the acknowledged position leaves it.
    pred: Option<Handle>,
    draining: bool,
    /// Bytes of an unfinished line.
    held: Vec<u8>,
    /// The offset just past the last line or piece handled.
    handled: u64,
    /// Whether the held line is being returned in pieces.
    splitting: bool,
    batch: Vec<Vec<u8>>,
    batch_bytes: usize,
    batch_end: Option<LogPosition>,
    /// The last position a result carried.
    reported: Option<LogPosition>,
    /// When the rotation being waited out was first seen.
    rotation_since: Option<Instant>,
    /// Whether a rotation not followed was logged.
    rotation_logged: bool,
    /// When bytes were last read.
    last_bytes: Instant,
    /// When to read or open next.
    next: Instant,
    last_problem: Option<Discriminant<Problem>>,
    /// The directory of the file last opened.
    last_dir: Option<PathBuf>,
    /// Whether `path` existed at the first attempt to open it.
    existed: Option<bool>,
    buf: Vec<u8>,
}

impl Reader {
    fn new(
        settings: Settings,
        results: mpsc::Sender<Output>,
        commands: std_mpsc::Receiver<Command>,
        number: u64,
    ) -> Self {
        let now = Instant::now();
        Self {
            settings,
            results,
            commands,
            number,
            gate: Gate::Paused,
            target: None,
            follow: None,
            pred: None,
            draining: false,
            held: Vec::new(),
            handled: 0,
            splitting: false,
            batch: Vec::new(),
            batch_bytes: 0,
            batch_end: None,
            reported: None,
            rotation_since: None,
            rotation_logged: false,
            last_bytes: now,
            next: now,
            last_problem: None,
            last_dir: None,
            existed: None,
            buf: vec![0; CHUNK],
        }
    }

    fn run(mut self, initial: Initial) {
        if let Initial::Load(state_dir) = initial {
            self.settings.hook.before(Step::Load, &self.settings.path);
            let loaded =
                checkpoints::load_log(&state_dir, &self.settings.kind, &self.settings.path);
            let checkpoint = match &loaded {
                Loaded::Found(position)
                | Loaded::Corrupt {
                    end: Some(position),
                    ..
                } => Some(*position),
                _ => None,
            };
            if self.send(Event::Loaded(loaded)).is_err() {
                return;
            }
            self.target = Some(checkpoint.map_or(Target::Start, Target::Resume));
        }
        let _ = self.main();
    }

    fn main(&mut self) -> Result<(), Closed> {
        loop {
            if Instant::now() >= self.next {
                self.step()?;
            }
            let timeout = self.next.saturating_duration_since(Instant::now());
            match self.commands.recv_timeout(timeout) {
                Ok(command) => {
                    self.command(command)?;
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return Err(Closed),
            }
        }
    }

    /// Opens the target, or reads, once.
    fn step(&mut self) -> Result<(), Closed> {
        self.next = Instant::now() + self.settings.poll;
        if let Some(target) = self.target.take() {
            match target {
                Target::Start => self.open_start()?,
                Target::Zero => self.open_zero()?,
                Target::Resume(position) => self.open_resume(position)?,
            }
            if self.target.is_some() {
                return Ok(());
            }
        }
        if self.gate == Gate::Open {
            self.read()?;
        }
        Ok(())
    }

    /// Applies a command. Returns whether it was a resume.
    fn command(&mut self, command: Command) -> Result<bool, Closed> {
        match command {
            Command::Resume { number, position } => {
                self.resume(number, position)?;
                Ok(true)
            }
            Command::Acknowledged(position) => {
                if !self.draining
                    && let Some(pred) = &self.pred
                    && pred.id != position.identity()
                {
                    debug!("Released the rotated-away file of {}", self.settings.kind);
                    self.pred = None;
                }
                Ok(false)
            }
            Command::Stop => Err(Closed),
        }
    }

    /// Applies the commands already sent. Returns whether one was a resume.
    fn poll_commands(&mut self) -> Result<bool, Closed> {
        let mut resumed = false;
        loop {
            match self.commands.try_recv() {
                Ok(command) => resumed |= self.command(command)?,
                Err(TryRecvError::Empty) => return Ok(resumed),
                Err(TryRecvError::Disconnected) => return Err(Closed),
            }
        }
    }

    fn send(&self, event: Event) -> Result<(), Closed> {
        self.results
            .blocking_send(Output {
                resume: self.number,
                event,
            })
            .map_err(|_| Closed)
    }

    /// Reports `problem`, unless it is the problem last reported.
    fn problem(&mut self, problem: Problem) -> Result<(), Closed> {
        let kind = discriminant(&problem);
        if self.last_problem == Some(kind) {
            return Ok(());
        }
        self.last_problem = Some(kind);
        self.send(Event::Problem(problem))
    }

    /// Reports a read error, discards what was read and not returned, and
    /// reads nothing until the next resume.
    fn read_failed(&mut self, error: &io::Error) -> Result<(), Closed> {
        self.discard();
        self.gate = Gate::Paused;
        self.last_problem = None;
        self.problem(Problem::Read(error.to_string()))
    }

    /// Discards the lines not returned and the held bytes.
    fn discard(&mut self) {
        self.batch.clear();
        self.batch_bytes = 0;
        self.batch_end = None;
        self.held.clear();
        self.splitting = false;
    }

    fn resume(&mut self, number: u64, position: LogPosition) -> Result<(), Closed> {
        self.number = number;
        self.discard();
        self.last_problem = None;
        self.rotation_since = None;
        self.next = Instant::now();
        let id = position.identity();
        if let Gate::Truncated(truncated) = self.gate
            && truncated == id
            && position.offset != 0
        {
            return self.send(Event::Truncated(LogPosition::at(id, 0)));
        }
        self.gate = Gate::Open;
        self.target = None;
        if self.follow.as_ref().is_some_and(|handle| handle.id == id) {
            self.pred = None;
            self.draining = false;
            return self.resume_on(false, position);
        }
        if self.pred.as_ref().is_some_and(|handle| handle.id == id) {
            self.draining = true;
            return self.resume_on(true, position);
        }
        self.follow = None;
        self.pred = None;
        self.draining = false;
        self.target = Some(Target::Resume(position));
        Ok(())
    }

    /// Resumes at `position` on the open predecessor, or the open followed
    /// file.
    fn resume_on(&mut self, pred: bool, position: LogPosition) -> Result<(), Closed> {
        let handle = if pred {
            self.pred.as_mut()
        } else {
            self.follow.as_mut()
        };
        let Some(handle) = handle else {
            return Ok(());
        };
        let id = handle.id;
        let len = match handle.file.metadata() {
            Ok(metadata) => metadata.len(),
            Err(error) => return self.read_failed(&error),
        };
        if len < position.offset {
            return self.truncated(id);
        }
        if let Err(error) = handle.file.seek(SeekFrom::Start(position.offset)) {
            return self.read_failed(&error);
        }
        handle.offset = position.offset;
        self.begin(id, position.offset)
    }

    /// Starts reading the file `id` at `offset`.
    fn begin(&mut self, id: Identity, offset: u64) -> Result<(), Closed> {
        self.discard();
        self.handled = offset;
        self.rotation_since = None;
        self.rotation_logged = false;
        self.last_bytes = Instant::now();
        self.last_problem = None;
        let position = LogPosition::at(id, offset);
        self.reported = Some(position);
        self.send(Event::Opened(position))
    }

    /// A new content epoch of the file `id` begins: the reader waits for a
    /// resume at its start.
    fn truncated(&mut self, id: Identity) -> Result<(), Closed> {
        self.discard();
        self.gate = Gate::Truncated(id);
        self.send(Event::Truncated(LogPosition::at(id, 0)))
    }

    /// Opens `path` with the opening checks.
    fn open(&mut self, path: &Path) -> Result<Opened, Problem> {
        let opened = open_checked(path, &self.settings.refused, &self.settings.hook)?;
        info!("Reading {} for {}", path.display(), self.settings.kind);
        self.last_dir = opened.real_path.parent().map(Path::to_path_buf);
        Ok(opened)
    }

    /// Follows the opened file from `offset`.
    fn adopt(&mut self, opened: Opened, offset: u64) -> Result<(), Closed> {
        let Opened { mut file, id, .. } = opened;
        if offset != 0
            && let Err(error) = file.seek(SeekFrom::Start(offset))
        {
            self.follow = None;
            return self.read_failed(&error);
        }
        self.follow = Some(Handle { file, id, offset });
        self.begin(id, offset)
    }

    fn open_start(&mut self) -> Result<(), Closed> {
        let path = self.settings.path.clone();
        match self.open(&path) {
            Ok(opened) => {
                let existed = *self.existed.get_or_insert(true);
                let offset = if existed && self.settings.start == StartPosition::End {
                    opened.len
                } else {
                    0
                };
                self.adopt(opened, offset)
            }
            Err(problem) => {
                if self.existed.is_none() {
                    self.existed = Some(!matches!(problem, Problem::Missing));
                }
                self.target = Some(Target::Start);
                self.problem(problem)
            }
        }
    }

    fn open_zero(&mut self) -> Result<(), Closed> {
        let path = self.settings.path.clone();
        match self.open(&path) {
            Ok(opened) => self.adopt(opened, 0),
            Err(problem) => {
                self.target = Some(Target::Zero);
                self.problem(problem)
            }
        }
    }

    /// Finds the file of `position` with no file open.
    fn open_resume(&mut self, position: LogPosition) -> Result<(), Closed> {
        let path = self.settings.path.clone();
        let id = position.identity();
        self.settings.hook.before(Step::Stat, &path);
        let candidate = fs::metadata(&path)
            .is_ok_and(|metadata| qualifies(Identity::of(&metadata), metadata.len(), position));
        if candidate {
            match self.open(&path) {
                Ok(opened) if opened.id == id => {
                    if opened.len < position.offset {
                        self.follow = Some(Handle {
                            file: opened.file,
                            id,
                            offset: 0,
                        });
                        return self.truncated(id);
                    }
                    return self.adopt(opened, position.offset);
                }
                Ok(opened) if qualifies(opened.id, opened.len, position) => {
                    info!(
                        "Resuming {} for {} by its inode only",
                        path.display(),
                        self.settings.kind
                    );
                    return self.adopt(opened, position.offset);
                }
                // `path` changed since it was inspected.
                Ok(_) => {}
                Err(problem) => {
                    self.target = Some(Target::Resume(position));
                    return self.problem(problem);
                }
            }
        }

        let (found, opened) = match self.search(position) {
            Search::Found(found, opened) => (found, opened),
            Search::Retry(problem) => {
                self.target = Some(Target::Resume(position));
                return match problem {
                    Some(problem) => self.problem(problem),
                    None => Ok(()),
                };
            }
            Search::Lost => {
                warn!(
                    "Cannot find the file {} was reading before {}; lines may have been lost",
                    self.settings.kind,
                    path.display()
                );
                return self.open_zero();
            }
        };
        info!("Reading {} for {}", found.display(), self.settings.kind);
        if opened.id != id {
            info!(
                "Resuming {} for {} by its inode only",
                found.display(),
                self.settings.kind
            );
        }
        self.last_dir = opened.real_path.parent().map(Path::to_path_buf);
        let Opened {
            mut file,
            id: found_id,
            len,
            ..
        } = opened;
        self.draining = true;
        if len < position.offset {
            // Only an exact match can be shorter: a new content epoch of
            // the predecessor, read from its start once it is saved.
            self.pred = Some(Handle {
                file,
                id: found_id,
                offset: 0,
            });
            return self.truncated(found_id);
        }
        if let Err(error) = file.seek(SeekFrom::Start(position.offset)) {
            self.draining = false;
            return self.read_failed(&error);
        }
        self.pred = Some(Handle {
            file,
            id: found_id,
            offset: position.offset,
        });
        self.begin(found_id, position.offset)
    }

    /// Looks for the file of `position` beside the file last opened, or
    /// beside `path` when nothing was opened yet.
    ///
    /// A candidate that cannot be opened, or a directory entry that cannot
    /// be inspected while no exact match is found, is not given up on: the
    /// search is tried again, so a predecessor that is only out of reach
    /// for a while is not taken for lost.
    fn search(&self, position: LogPosition) -> Search {
        let path = &self.settings.path;
        let Some(dir) = self
            .last_dir
            .clone()
            .or_else(|| {
                fs::canonicalize(path)
                    .ok()
                    .and_then(|real| real.parent().map(Path::to_path_buf))
            })
            .or_else(|| path.parent().map(Path::to_path_buf))
        else {
            return Search::Lost;
        };
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Search::Lost,
            Err(error) => {
                return Search::Retry(Some(Problem::Stat(io::Error::new(
                    error.kind(),
                    format!("{}: {error}", dir.display()),
                ))));
            }
        };
        let id = position.identity();
        let mut exact = Vec::new();
        let mut inode = Vec::new();
        // An entry that cannot be inspected may be the file sought.
        let mut failure = None;
        for entry in entries {
            let inspected = entry.and_then(|entry| {
                let candidate = entry.path();
                fs::symlink_metadata(&candidate).map(|metadata| (candidate, metadata))
            });
            let (candidate, metadata) = match inspected {
                Ok(inspected) => inspected,
                // It was removed since the directory was listed.
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => {
                    failure.get_or_insert(error);
                    continue;
                }
            };
            if !metadata.is_file() {
                continue;
            }
            let found = Identity::of(&metadata);
            if found == id {
                exact.push(candidate);
            } else if qualifies(found, metadata.len(), position) {
                inode.push(candidate);
            }
        }
        if exact.is_empty()
            && let Some(error) = failure
        {
            return Search::Retry(Some(Problem::Stat(io::Error::new(
                error.kind(),
                format!("{}: {error}", dir.display()),
            ))));
        }
        for candidate in exact.into_iter().chain(inode) {
            match open_checked(&candidate, &self.settings.refused, &self.settings.hook) {
                Ok(opened) if qualifies(opened.id, opened.len, position) => {
                    return Search::Found(candidate, opened);
                }
                // The candidate was replaced since it was inspected.
                Ok(_) => {}
                // It was renamed since: the next search finds it again.
                Err(Problem::Missing) => return Search::Retry(None),
                Err(problem) => return Search::Retry(Some(problem)),
            }
        }
        Search::Lost
    }

    /// Reads the file being read until EOF, and then follows it.
    fn read(&mut self) -> Result<(), Closed> {
        loop {
            let draining = self.draining;
            let Some(id) = self.active().map(|handle| handle.id) else {
                return Ok(());
            };
            match self.read_to_eof()? {
                Read::Eof => {}
                Read::Interrupted => return Ok(()),
                Read::Failed(error) => return self.read_failed(&error),
            }
            self.flush(id)?;
            let switched = if draining {
                self.finish_drain()?
            } else {
                self.check_path()?
            };
            if !switched {
                return Ok(());
            }
        }
    }

    /// The file being read.
    fn active(&mut self) -> Option<&mut Handle> {
        if self.draining {
            self.pred.as_mut()
        } else {
            self.follow.as_mut()
        }
    }

    fn read_to_eof(&mut self) -> Result<Read, Closed> {
        let mut buf = std::mem::take(&mut self.buf);
        let result = self.read_chunks(&mut buf);
        self.buf = buf;
        result
    }

    fn read_chunks(&mut self, buf: &mut [u8]) -> Result<Read, Closed> {
        loop {
            if self.poll_commands()? {
                return Ok(Read::Interrupted);
            }
            let Some(handle) = self.active() else {
                return Ok(Read::Eof);
            };
            let read = match handle.file.read(buf) {
                Ok(0) => return Ok(Read::Eof),
                Ok(read) => read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Ok(Read::Failed(error)),
            };
            handle.offset += read as u64;
            let id = handle.id;
            self.last_bytes = Instant::now();
            self.feed(&buf[..read], id)?;
        }
    }

    /// Assembles lines from bytes read from the file `id`.
    fn feed(&mut self, mut chunk: &[u8], id: Identity) -> Result<(), Closed> {
        while !chunk.is_empty() {
            let newline = chunk.iter().position(|&byte| byte == b'\n');
            let segment = newline.unwrap_or(chunk.len());
            if let Some(newline) = newline
                && self.held.len() + segment <= MAX_HELD
            {
                let mut line = std::mem::take(&mut self.held);
                line.extend_from_slice(&chunk[..newline]);
                chunk = &chunk[newline + 1..];
                self.handled += line.len() as u64 + 1;
                self.splitting = false;
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                if !line.is_empty() {
                    self.push(line, id)?;
                }
            } else {
                let take = segment.min(MAX_HELD - self.held.len());
                self.held.extend_from_slice(&chunk[..take]);
                chunk = &chunk[take..];
                if self.held.len() == MAX_HELD {
                    if !self.splitting {
                        debug!(
                            "Splitting a line of {} longer than {MAX_HELD} bytes into pieces",
                            self.settings.kind
                        );
                        self.splitting = true;
                    }
                    let piece = std::mem::take(&mut self.held);
                    self.handled += piece.len() as u64;
                    self.push(piece, id)?;
                }
            }
        }
        Ok(())
    }

    /// Adds a line ending at the handled offset to the batch.
    fn push(&mut self, line: Vec<u8>, id: Identity) -> Result<(), Closed> {
        if !self.batch.is_empty() && self.batch_bytes + line.len() > BATCH_BYTES {
            self.send_batch()?;
        }
        self.batch_bytes += line.len();
        self.batch.push(line);
        self.batch_end = Some(LogPosition::at(id, self.handled));
        if self.batch.len() >= BATCH_LINES {
            self.send_batch()?;
        }
        Ok(())
    }

    fn send_batch(&mut self) -> Result<(), Closed> {
        let Some(end) = self.batch_end.take() else {
            return Ok(());
        };
        let lines = std::mem::take(&mut self.batch);
        self.batch_bytes = 0;
        self.reported = Some(end);
        self.send(Event::Batch { lines, end })
    }

    /// Returns the lines of the file `id` not returned yet, and reports the
    /// bytes consumed past them.
    fn flush(&mut self, id: Identity) -> Result<(), Closed> {
        self.send_batch()?;
        let position = LogPosition::at(id, self.handled);
        if self.reported != Some(position) {
            self.reported = Some(position);
            self.send(Event::Position(position))?;
        }
        Ok(())
    }

    /// Returns the held bytes of the file `id` as a final line.
    fn final_line(&mut self, id: Identity) -> Result<(), Closed> {
        if !self.held.is_empty() {
            let line = std::mem::take(&mut self.held);
            self.handled += line.len() as u64;
            self.splitting = false;
            self.push(line, id)?;
        }
        self.flush(id)
    }

    /// Compares `path` with the followed file at EOF. Returns whether the
    /// reader switched to a new file.
    fn check_path(&mut self) -> Result<bool, Closed> {
        let Some(follow) = &self.follow else {
            return Ok(false);
        };
        let (id, offset) = (follow.id, follow.offset);
        let path = &self.settings.path;
        self.settings.hook.before(Step::Stat, path);
        let Ok(metadata) = fs::metadata(path) else {
            // Missing: the open file is read again.
            return Ok(false);
        };
        if Identity::of(&metadata) == id {
            self.rotation_since = None;
            self.rotation_logged = false;
            if metadata.len() < offset {
                self.truncated(id)?;
            }
            return Ok(false);
        }
        if self.pred.is_some() {
            if !self.rotation_logged {
                debug!(
                    "Not following a rotation of {} for {} while the rotated-away file is held",
                    path.display(),
                    self.settings.kind
                );
                self.rotation_logged = true;
            }
            return Ok(false);
        }
        let now = Instant::now();
        let since = *self.rotation_since.get_or_insert(now);
        if now.duration_since(since.max(self.last_bytes)) < self.settings.poll {
            return Ok(false);
        }
        self.switch(id)
    }

    /// Switches from the drained file `id` to the file `path` names.
    ///
    /// Held bytes are returned as a final line only once the switch is
    /// made: until then, the old file may still complete the line.
    fn switch(&mut self, id: Identity) -> Result<bool, Closed> {
        let path = self.settings.path.clone();
        match self.open(&path) {
            // `path` names the file read again.
            Ok(opened) if opened.id == id => {
                self.rotation_since = None;
                Ok(false)
            }
            Ok(opened) => {
                self.final_line(id)?;
                self.pred = self.follow.take();
                self.draining = false;
                self.adopt(opened, 0)?;
                Ok(true)
            }
            Err(problem) => {
                self.problem(problem)?;
                Ok(false)
            }
        }
    }

    /// Continues with the followed file from 0 once the predecessor is
    /// drained. Returns whether the reader switched.
    ///
    /// As at a rotation, held bytes are returned as a final line only once
    /// the switch is made.
    fn finish_drain(&mut self) -> Result<bool, Closed> {
        let Some(pred) = &self.pred else {
            return Ok(false);
        };
        let id = pred.id;
        if let Some(mut follow) = self.follow.take() {
            if let Err(error) = follow.file.seek(SeekFrom::Start(0)) {
                self.follow = Some(follow);
                self.read_failed(&error)?;
                return Ok(false);
            }
            self.final_line(id)?;
            follow.offset = 0;
            let next = follow.id;
            self.follow = Some(follow);
            self.draining = false;
            self.begin(next, 0)?;
            return Ok(true);
        }
        let path = self.settings.path.clone();
        match self.open(&path) {
            // `path` names the predecessor itself: it is followed.
            Ok(opened) if opened.id == id => {
                self.follow = self.pred.take();
                self.draining = false;
                Ok(false)
            }
            Ok(opened) => {
                self.final_line(id)?;
                self.draining = false;
                self.adopt(opened, 0)?;
                Ok(true)
            }
            Err(problem) => {
                self.problem(problem)?;
                Ok(false)
            }
        }
    }
}

/// What the search for a predecessor found.
enum Search {
    /// The file, and where it was found.
    Found(PathBuf, Opened),
    /// A candidate could not be opened, or an entry could not be
    /// inspected: the search is tried again, after reporting the problem,
    /// if any.
    Retry(Option<Problem>),
    /// No file holds the position.
    Lost,
}

/// How reading to EOF ended.
enum Read {
    Eof,
    /// A resume changed what is read.
    Interrupted,
    Failed(io::Error),
}

/// Tells whether a file `found` of length `len` holds `position`: the same
/// device and inode, or the same inode in a file at least as long as the
/// offset.
fn qualifies(found: Identity, len: u64, position: LogPosition) -> bool {
    found == position.identity() || (found.ino == position.ino && len >= position.offset)
}

#[cfg(all(test, unix))]
mod tests {
    use std::io::Write as _;
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    use tempfile::TempDir;
    use tokio::time::timeout;

    use super::*;

    /// The poll interval of the readers under test.
    const POLL: Duration = Duration::from_millis(300);
    /// How long a test waits for something that should happen.
    const WAIT: Duration = Duration::from_secs(10);

    /// Captures what is logged on this thread and on the reader threads
    /// spawned from it.
    #[derive(Clone, Default)]
    struct Logs(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Logs {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().expect("lock").extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Logs {
        fn capture() -> (Self, tracing::subscriber::DefaultGuard) {
            let logs = Self::default();
            let writer = logs.clone();
            let subscriber = tracing_subscriber::fmt()
                .with_ansi(false)
                .with_max_level(tracing::Level::DEBUG)
                .with_writer(move || writer.clone())
                .finish();
            (logs, tracing::subscriber::set_default(subscriber))
        }

        fn text(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().expect("lock")).into_owned()
        }
    }

    /// A reader under test.
    struct Run {
        reader: ReaderLink,
        /// The number of the last resume sent.
        resume: u64,
    }

    struct Options {
        start: StartPosition,
        refused: Vec<RefusedDir>,
        hook: Hook,
        /// The state directory to load the checkpoint from, or `None` for a
        /// reader that waits for its first resume.
        load: Option<PathBuf>,
    }

    impl Default for Options {
        fn default() -> Self {
            Self {
                start: StartPosition::Beginning,
                refused: Vec::new(),
                hook: Hook::default(),
                load: None,
            }
        }
    }

    impl Run {
        fn start(path: &Path, options: Options) -> Self {
            let settings = Settings {
                kind: "kind_a".to_string(),
                path: path.to_path_buf(),
                start: options.start,
                poll: POLL,
                refused: options.refused.into(),
                hook: options.hook,
            };
            let initial = options.load.map_or(Initial::Wait, Initial::Load);
            let reader = spawn(settings, initial, 0).expect("the reader starts");
            Self { reader, resume: 0 }
        }

        /// Starts a reader that loads its checkpoint from `state`.
        fn loading(path: &Path, state: &Path, start: StartPosition) -> Self {
            Self::start(
                path,
                Options {
                    start,
                    load: Some(state.to_path_buf()),
                    ..Options::default()
                },
            )
        }

        async fn output(&mut self) -> Output {
            timeout(WAIT, self.reader.results.recv())
                .await
                .expect("a result in time")
                .expect("the reader runs")
        }

        /// The next result, which follows the last resume.
        async fn next(&mut self) -> Event {
            let output = self.output().await;
            assert_eq!(output.resume, self.resume, "{output:?}");
            output.event
        }

        /// The next result that follows the last resume, skipping earlier
        /// ones.
        async fn current(&mut self) -> Event {
            loop {
                let output = self.output().await;
                if output.resume == self.resume {
                    return output.event;
                }
                assert!(output.resume < self.resume, "{output:?}");
            }
        }

        /// The next batch, skipping positions.
        async fn batch(&mut self) -> (Vec<String>, LogPosition) {
            loop {
                match self.current().await {
                    Event::Batch { lines, end } => {
                        let lines = lines
                            .iter()
                            .map(|line| String::from_utf8_lossy(line).into_owned())
                            .collect();
                        return (lines, end);
                    }
                    Event::Position(_) => {}
                    other => panic!("expected a batch, found {other:?}"),
                }
            }
        }

        /// The next result that is not a position.
        async fn event(&mut self) -> Event {
            loop {
                match self.current().await {
                    Event::Position(_) => {}
                    other => return other,
                }
            }
        }

        /// Asserts that no result other than a position arrives within
        /// `within`.
        async fn quiet(&mut self, within: Duration) {
            let deadline = tokio::time::Instant::now() + within;
            while let Ok(output) =
                tokio::time::timeout_at(deadline, self.reader.results.recv()).await
            {
                let output = output.expect("the reader runs");
                assert!(
                    matches!(output.event, Event::Position(_)),
                    "unexpected {output:?}"
                );
            }
        }

        fn resume(&mut self, position: LogPosition) {
            self.resume += 1;
            self.reader.send(Command::Resume {
                number: self.resume,
                position,
            });
        }
    }

    fn position(path: &Path, offset: u64) -> LogPosition {
        LogPosition::new(&fs::metadata(path).expect("the file exists"), offset)
    }

    fn append(path: &Path, bytes: &[u8]) {
        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)
            .expect("the file opens");
        file.write_all(bytes).expect("written");
    }

    fn mkfifo(path: &Path) {
        use std::os::unix::ffi::OsStrExt;

        let path = std::ffi::CString::new(path.as_os_str().as_bytes()).expect("no NUL");
        // SAFETY: `path` is a valid NUL-terminated string.
        let result = unsafe { libc::mkfifo(path.as_ptr(), 0o644) };
        assert_eq!(result, 0, "mkfifo");
    }

    /// Counts the open file descriptors of this process that name a file
    /// under `dir`.
    fn open_files_under(dir: &Path) -> usize {
        let dir = fs::canonicalize(dir).expect("the directory exists");
        open_paths()
            .iter()
            .filter(|path| path.starts_with(&dir))
            .count()
    }

    #[cfg(target_os = "linux")]
    fn open_paths() -> Vec<PathBuf> {
        fs::read_dir("/proc/self/fd")
            .expect("/proc/self/fd")
            .flatten()
            .filter_map(|entry| fs::read_link(entry.path()).ok())
            .collect()
    }

    #[cfg(not(target_os = "linux"))]
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

    /// Calls `f` before each step of the reader at `path`.
    fn hook(path: &Path, f: impl Fn(Step) + Send + Sync + 'static) -> Hook {
        let path = path.to_path_buf();
        Hook {
            before: Some(Arc::new(move |step, at: &Path| {
                if at == path {
                    f(step);
                }
            })),
        }
    }

    /// Renames `path` to `to` and creates `path` again holding `bytes`.
    fn rotate(path: &Path, to: &Path, bytes: &[u8]) {
        fs::rename(path, to).expect("renamed");
        fs::write(path, bytes).expect("created");
    }

    /// Resumes the reader at `offset` of `path` and takes its `Opened`.
    async fn resume_at(run: &mut Run, path: &Path, offset: u64) {
        let at = position(path, offset);
        run.resume(at);
        assert_opened(run.next().await, at);
    }

    fn assert_opened(event: Event, expected: LogPosition) {
        match event {
            Event::Opened(position) => assert_eq!(position, expected),
            other => panic!("expected Opened({expected:?}), found {other:?}"),
        }
    }

    fn assert_truncated(event: Event, expected: LogPosition) {
        match event {
            Event::Truncated(position) => assert_eq!(position, expected),
            other => panic!("expected Truncated({expected:?}), found {other:?}"),
        }
    }

    fn assert_problem(event: Event, reason: &str) {
        match event {
            Event::Problem(problem) => assert_eq!(problem.reason(), reason),
            other => panic!("expected a problem, found {other:?}"),
        }
    }

    /// Returns the lines `line` makes of `indices`, each ended by `\n`.
    fn numbered(indices: std::ops::Range<usize>, line: impl Fn(usize) -> String) -> String {
        indices
            .map(line)
            .flat_map(|line| [line, "\n".to_string()])
            .collect()
    }

    /// A directory with `a.log` holding `bytes`, and a state directory.
    fn files(bytes: &[u8]) -> (TempDir, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("a.log");
        fs::write(&path, bytes).expect("written");
        let state = dir.path().join("state");
        fs::create_dir(&state).expect("created");
        (dir, path, state)
    }

    #[tokio::test]
    async fn follows_appended_lines() {
        let (_dir, path, state) = files(b"a1\r\n\na2\n");
        let mut run = Run::loading(&path, &state, StartPosition::Beginning);
        assert!(matches!(run.next().await, Event::Loaded(Loaded::Missing)));
        assert_opened(run.next().await, position(&path, 0));
        // Nothing is read before the first resume.
        run.quiet(POLL * 2).await;

        resume_at(&mut run, &path, 0).await;
        assert_eq!(
            run.batch().await,
            (vec!["a1".into(), "a2".into()], position(&path, 8))
        );
        append(&path, b"a3\n\n");
        assert_eq!(run.batch().await, (vec!["a3".into()], position(&path, 11)));
        // The empty line is consumed and reported.
        match run.next().await {
            Event::Position(at) => assert_eq!(at, position(&path, 12)),
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn start_end_skips_existing_lines_and_a_late_file_is_read_from_its_beginning() {
        let (dir, path, state) = files(b"e1\n");
        let mut run = Run::loading(&path, &state, StartPosition::End);
        assert!(matches!(run.next().await, Event::Loaded(Loaded::Missing)));
        assert_opened(run.next().await, position(&path, 3));
        resume_at(&mut run, &path, 3).await;
        append(&path, b"e2\n");
        assert_eq!(run.batch().await.0, ["e2"]);

        // A path missing at the first attempt is read from 0 when it
        // appears, whatever `start` says.
        let late = dir.path().join("late.log");
        let mut run = Run::loading(&late, &state, StartPosition::End);
        assert!(matches!(run.next().await, Event::Loaded(Loaded::Missing)));
        assert_problem(run.next().await, "the path does not exist");
        run.quiet(POLL * 2).await;
        fs::write(&late, b"m1\nm2\n").expect("written");
        assert_opened(run.next().await, position(&late, 0));
        resume_at(&mut run, &late, 0).await;
        assert_eq!(run.batch().await.0, ["m1", "m2"]);
    }

    #[tokio::test]
    async fn a_checkpoint_is_resumed_and_start_ignored() {
        let (_dir, path, state) = files(b"a1\na2\n");
        let kind_dir = state.join("checkpoints").join("log");
        fs::create_dir_all(&kind_dir).expect("created");
        let metadata = fs::metadata(&path).expect("exists");
        let at = LogPosition::new(&metadata, 3);
        fs::write(
            kind_dir.join("kind_a.json"),
            format!(
                "{{\"type\":\"log\",\"kind\":\"kind_a\",\"path\":\"{}\",\"dev\":{},\"ino\":{},\"offset\":3}}",
                path.display(),
                at.dev,
                at.ino
            ),
        )
        .expect("written");
        let mut run = Run::loading(&path, &state, StartPosition::End);
        assert!(matches!(run.next().await, Event::Loaded(Loaded::Found(found)) if found == at));
        assert_opened(run.next().await, at);
        resume_at(&mut run, &path, 3).await;
        assert_eq!(run.batch().await.0, ["a2"]);
    }

    #[tokio::test]
    async fn follows_a_rename_rotation_with_late_writes_to_the_renamed_file() {
        let (dir, path, _state) = files(b"a1\n");
        let (stats, checks) = std::sync::mpsc::channel();
        let stats = Mutex::new(stats);
        let mut run = Run::start(
            &path,
            Options {
                hook: hook(&path, move |step| {
                    if step == Step::Stat {
                        let _ = stats.lock().expect("lock").send(());
                    }
                }),
                ..Options::default()
            },
        );
        resume_at(&mut run, &path, 0).await;
        assert_eq!(run.batch().await.0, ["a1"]);
        let old = position(&path, 0);

        let renamed = dir.path().join("a.log.1");
        rotate(&path, &renamed, b"b1\n");
        // Once the reader has seen the rotation, the producer still writes
        // to the renamed file within the quiet interval.
        while checks.try_recv().is_ok() {}
        checks
            .recv_timeout(WAIT)
            .expect("the reader checks the path");
        append(&renamed, b"a2\npartial");
        let (lines, end) = run.batch().await;
        assert_eq!(lines, ["a2"]);
        assert_eq!(end.identity(), old.identity());
        // The held bytes are the old file's final line.
        let (lines, end) = run.batch().await;
        assert_eq!(lines, ["partial"]);
        assert_eq!(end, LogPosition { offset: 13, ..old });
        assert_opened(run.event().await, position(&path, 0));
        assert_eq!(run.batch().await.0, ["b1"]);
    }

    #[tokio::test]
    async fn a_copy_truncate_waits_for_a_resume_at_the_start() {
        let (dir, path, _state) = files(b"a1\na2\n");
        let mut run = Run::start(&path, Options::default());
        resume_at(&mut run, &path, 0).await;
        assert_eq!(run.batch().await.0, ["a1", "a2"]);

        fs::copy(&path, dir.path().join("a.log.1")).expect("copied");
        OpenOptions::new()
            .write(true)
            .open(&path)
            .and_then(|file| file.set_len(0))
            .expect("truncated");
        append(&path, b"b1\n");
        assert_truncated(run.event().await, position(&path, 0));
        // Nothing of the new content is read before the resume.
        run.quiet(POLL * 3).await;
        // A resume at the old offset is answered with the truncation again.
        run.resume(position(&path, 6));
        assert_truncated(run.next().await, position(&path, 0));
        resume_at(&mut run, &path, 0).await;
        assert_eq!(run.batch().await.0, ["b1"]);
    }

    #[tokio::test]
    async fn a_truncation_gives_way_to_a_resume_on_the_held_predecessor() {
        let (dir, path, _state) = files(b"a1\n");
        let mut run = Run::start(&path, Options::default());
        resume_at(&mut run, &path, 0).await;
        assert_eq!(run.batch().await.0, ["a1"]);
        let old = position(&path, 3);
        let renamed = dir.path().join("a.log.1");
        rotate(&path, &renamed, b"b1 a longer line\n");
        assert_opened(run.event().await, position(&path, 0));
        assert_eq!(run.batch().await.0, ["b1 a longer line"]);

        // The new file is truncated while the rotated-away one is held.
        OpenOptions::new()
            .write(true)
            .open(&path)
            .and_then(|file| file.set_len(0))
            .expect("truncated");
        append(&path, b"c1\n");
        assert_truncated(run.event().await, position(&path, 0));
        append(&renamed, b"a2\n");

        // A resume at the acknowledged position on the predecessor, as after
        // a stream replacement that dropped the truncation: the predecessor
        // is drained, and the truncated file is read from its beginning.
        run.resume(old);
        assert_opened(run.next().await, old);
        assert_eq!(run.batch().await.0, ["a2"]);
        assert_opened(run.event().await, position(&path, 0));
        assert_eq!(run.batch().await.0, ["c1"]);
    }

    #[tokio::test]
    async fn a_file_replaced_in_place_by_a_shorter_one_is_a_truncation() {
        let (_dir, path, _state) = files(b"long line 1\nlong line 2\n");
        let mut run = Run::start(&path, Options::default());
        resume_at(&mut run, &path, 0).await;
        assert_eq!(run.batch().await.0.len(), 2);
        let id = position(&path, 0);
        fs::write(&path, b"z\n").expect("rewritten");
        assert_eq!(position(&path, 0), id, "the same inode");
        assert_truncated(run.event().await, id);
        resume_at(&mut run, &path, 0).await;
        assert_eq!(run.batch().await.0, ["z"]);
    }

    #[tokio::test]
    async fn a_missing_path_keeps_the_open_file() {
        let (dir, path, _state) = files(b"a1\n");
        let mut run = Run::start(&path, Options::default());
        resume_at(&mut run, &path, 0).await;
        assert_eq!(run.batch().await.0, ["a1"]);
        let renamed = dir.path().join("a.log.1");
        fs::rename(&path, &renamed).expect("renamed");
        append(&renamed, b"a2\n");
        assert_eq!(run.batch().await.0, ["a2"]);
        run.quiet(POLL * 3).await;
        fs::write(&path, b"b1\n").expect("created");
        assert_opened(run.event().await, position(&path, 0));
        assert_eq!(run.batch().await.0, ["b1"]);
    }

    #[tokio::test]
    async fn a_repointed_symlink_is_a_rotation() {
        let (dir, _path, _state) = files(b"");
        let first = dir.path().join("first.log");
        let second = dir.path().join("second.log");
        fs::write(&first, b"t1\n").expect("written");
        fs::write(&second, b"t2\n").expect("written");
        let link = dir.path().join("link.log");
        symlink(&first, &link).expect("linked");
        let mut run = Run::start(&link, Options::default());
        resume_at(&mut run, &first, 0).await;
        assert_eq!(run.batch().await.0, ["t1"]);
        fs::remove_file(&link).expect("removed");
        symlink(&second, &link).expect("linked");
        assert_opened(run.event().await, position(&second, 0));
        assert_eq!(run.batch().await.0, ["t2"]);
    }

    #[tokio::test]
    async fn files_under_a_refused_directory_are_refused() {
        let (dir, _path, state) = files(b"");
        let secret = dir.path().join("secret");
        fs::create_dir(&secret).expect("created");
        let key = secret.join("key.pem");
        fs::write(&key, b"secret line\n").expect("written");
        let link = dir.path().join("link.log");
        symlink(&key, &link).expect("linked");
        let name = secret.to_string_lossy().into_owned();

        for path in [&key, &link] {
            let mut run = Run::start(
                path,
                Options {
                    refused: refused_dirs(&[&name]),
                    load: Some(state.clone()),
                    ..Options::default()
                },
            );
            assert!(matches!(run.next().await, Event::Loaded(_)));
            assert_problem(
                run.next().await,
                &format!("the file lies under the refused directory {name}"),
            );
            // Nothing is opened, so nothing can be read.
            run.quiet(POLL * 2).await;
        }
    }

    #[tokio::test]
    async fn a_fifo_never_blocks_the_reader() {
        let (dir, path, state) = files(b"a1\n");
        let fifo = dir.path().join("fifo.log");
        mkfifo(&fifo);
        let mut run = Run::loading(&fifo, &state, StartPosition::Beginning);
        assert!(matches!(run.next().await, Event::Loaded(_)));
        assert_problem(run.next().await, "the path is not a regular file");

        // A FIFO swapped in between the inspection and the open.
        let swapped = AtomicBool::new(false);
        let target = path.clone();
        let mut run = Run::start(
            &path,
            Options {
                hook: hook(&path, move |step| {
                    if step == Step::Open && !swapped.swap(true, Ordering::SeqCst) {
                        fs::remove_file(&target).expect("removed");
                        mkfifo(&target);
                    }
                }),
                load: Some(state),
                ..Options::default()
            },
        );
        assert!(matches!(run.next().await, Event::Loaded(_)));
        assert_problem(run.next().await, "the path is not a regular file");
        run.quiet(POLL * 2).await;
    }

    #[tokio::test]
    async fn a_partial_line_is_held_until_completed() {
        let (dir, path, _state) = files(b"p1");
        let mut run = Run::start(&path, Options::default());
        resume_at(&mut run, &path, 0).await;
        run.quiet(POLL * 2).await;
        append(&path, b"p2\n");
        assert_eq!(run.batch().await, (vec!["p1p2".into()], position(&path, 5)));

        // At a rotation it is sent as the old file's final line.
        append(&path, b"tail");
        rotate(&path, &dir.path().join("a.log.1"), b"n1\n");
        let (lines, end) = run.batch().await;
        assert_eq!(lines, ["tail"]);
        assert_eq!(end.offset, 9);
        assert_opened(run.event().await, position(&path, 0));
        assert_eq!(run.batch().await.0, ["n1"]);
    }

    #[tokio::test]
    async fn a_partial_line_is_kept_while_a_rotation_cannot_be_followed() {
        let (dir, path, _state) = files(b"part");
        let renamed = dir.path().join("a.log.1");
        let mut run = Run::start(&path, Options::default());
        resume_at(&mut run, &path, 0).await;
        run.quiet(POLL * 2).await;

        // The new file cannot be opened: the old one is still read, and the
        // held bytes stay a part of its unfinished line.
        fs::rename(&path, &renamed).expect("renamed");
        mkfifo(&path);
        assert_problem(run.event().await, "the path is not a regular file");
        append(&renamed, b"ial\n");
        assert_eq!(run.batch().await.0, ["partial"]);

        fs::remove_file(&path).expect("removed");
        fs::write(&path, b"n1\n").expect("created");
        assert_opened(run.event().await, position(&path, 0));
        assert_eq!(run.batch().await.0, ["n1"]);
    }

    #[tokio::test]
    async fn a_partial_line_is_kept_while_a_drained_predecessor_cannot_be_left() {
        let (dir, path, _state) = files(b"a1\npart");
        let old = position(&path, 3);
        let renamed = dir.path().join("a.log.1");
        fs::rename(&path, &renamed).expect("renamed");
        mkfifo(&path);
        let mut run = Run::start(&path, Options::default());
        run.resume(old);
        assert_opened(run.next().await, old);
        assert_problem(run.event().await, "the path is not a regular file");
        append(&renamed, b"ial\n");
        assert_eq!(run.batch().await.0, ["partial"]);

        fs::remove_file(&path).expect("removed");
        fs::write(&path, b"b1\n").expect("created");
        assert_opened(run.event().await, position(&path, 0));
        assert_eq!(run.batch().await.0, ["b1"]);
    }

    #[tokio::test]
    async fn a_long_line_is_split_into_pieces() {
        let mut bytes = vec![b'x'; MAX_HELD + 10];
        bytes.push(b'\n');
        let (_dir, path, _state) = files(&bytes);
        let mut run = Run::start(&path, Options::default());
        resume_at(&mut run, &path, 0).await;
        let (lines, end) = run.batch().await;
        assert_eq!(
            lines.iter().map(String::len).collect::<Vec<_>>(),
            [MAX_HELD, 10]
        );
        assert_eq!(end, position(&path, bytes.len() as u64));
    }

    #[tokio::test]
    async fn batches_hold_at_most_1000_lines_or_4_mib() {
        let lines = numbered(0..2500, |index| format!("l{index}"));
        let (_dir, path, _state) = files(lines.as_bytes());
        let mut run = Run::start(&path, Options::default());
        resume_at(&mut run, &path, 0).await;
        let mut sizes = Vec::new();
        while sizes.iter().sum::<usize>() < 2500 {
            sizes.push(run.batch().await.0.len());
        }
        assert_eq!(sizes, [1000, 1000, 500]);

        let mut long = vec![b'y'; MAX_HELD - 1];
        long.push(b'\n');
        for _ in 0..5 {
            append(&path, &long);
        }
        let mut sizes = Vec::new();
        while sizes.iter().sum::<usize>() < 5 {
            let (lines, _) = run.batch().await;
            assert!(lines.iter().map(String::len).sum::<usize>() <= BATCH_BYTES);
            sizes.push(lines.len());
        }
        assert_eq!(sizes, [4, 1]);
    }

    #[tokio::test]
    async fn a_rotation_is_not_followed_while_the_rotated_away_file_is_held() {
        let (logs, _guard) = Logs::capture();
        let (dir, path, _state) = files(b"a1\n");
        let mut run = Run::start(&path, Options::default());
        resume_at(&mut run, &path, 0).await;
        assert_eq!(run.batch().await.0, ["a1"]);

        rotate(&path, &dir.path().join("a.log.1"), b"b1\n");
        assert_opened(run.event().await, position(&path, 0));
        assert_eq!(run.batch().await.0, ["b1"]);
        assert_eq!(open_files_under(dir.path()), 2);

        rotate(&path, &dir.path().join("a.log.2"), b"c1\n");
        run.quiet(POLL * 4).await;
        assert_eq!(open_files_under(dir.path()), 2);
        assert!(
            logs.text().contains("Not following a rotation"),
            "{}",
            logs.text()
        );

        // The acknowledged position leaves the rotated-away file for the
        // file read now, which was renamed in turn.
        let b = position(&dir.path().join("a.log.2"), 3);
        run.reader.send(Command::Acknowledged(b));
        assert_opened(run.event().await, position(&path, 0));
        assert_eq!(run.batch().await.0, ["c1"]);
        assert_eq!(open_files_under(dir.path()), 2);
        assert!(logs.text().contains("Released the rotated-away file"));
    }

    #[tokio::test]
    async fn resumes_on_the_open_file_and_with_none() {
        let (_dir, path, _state) = files(b"a1\na2\n");
        let mut run = Run::start(&path, Options::default());
        resume_at(&mut run, &path, 0).await;
        assert_eq!(run.batch().await.0, ["a1", "a2"]);
        // Through the open handle: only the suffix is read again.
        resume_at(&mut run, &path, 3).await;
        assert_eq!(run.batch().await.0, ["a2"]);
        append(&path, b"a3\n");
        assert_eq!(run.batch().await.0, ["a3"]);

        // With no open handle: the path is opened at the offset.
        let mut run = Run::start(&path, Options::default());
        resume_at(&mut run, &path, 3).await;
        assert_eq!(run.batch().await.0, ["a2", "a3"]);
    }

    #[tokio::test]
    async fn finds_a_renamed_predecessor() {
        let (logs, _guard) = Logs::capture();
        let (dir, path, _state) = files(b"a1\na2\n");
        let old = position(&path, 3);
        let renamed = dir.path().join("a.log.1");
        rotate(&path, &renamed, b"b1\n");
        let mut run = Run::start(&path, Options::default());
        run.resume(old);
        assert_opened(run.next().await, old);
        assert_eq!(run.batch().await.0, ["a2"]);
        assert_opened(run.event().await, position(&path, 0));
        assert_eq!(run.batch().await.0, ["b1"]);
        assert!(
            logs.text().contains(&format!(
                "Reading {} for kind_a",
                fs::canonicalize(&renamed).expect("resolves").display()
            )),
            "{}",
            logs.text()
        );
        // The drained predecessor is held as the rotated-away file.
        assert_eq!(open_files_under(dir.path()), 2);
    }

    #[tokio::test]
    async fn a_shorter_predecessor_found_by_the_search_is_a_truncation() {
        let (dir, path, _state) = files(b"a1\na2\n");
        let old = position(&path, 6);
        let renamed = dir.path().join("a.log.1");
        rotate(&path, &renamed, b"b1\n");
        // Truncated in place: the same inode, shorter than the offset.
        fs::write(&renamed, b"c1\n").expect("truncated");
        let mut run = Run::start(&path, Options::default());
        run.resume(old);
        assert_truncated(run.next().await, position(&renamed, 0));
        // Nothing of the new content is read before the resume at its
        // start.
        run.quiet(POLL * 2).await;
        resume_at(&mut run, &renamed, 0).await;
        assert_eq!(run.batch().await.0, ["c1"]);
        assert_opened(run.event().await, position(&path, 0));
        assert_eq!(run.batch().await.0, ["b1"]);
    }

    #[tokio::test]
    async fn a_predecessor_that_cannot_be_opened_is_searched_for_again() {
        let (logs, _guard) = Logs::capture();
        let (dir, path, _state) = files(b"a1\na2\n");
        let old = position(&path, 3);
        let renamed = dir.path().join("a.log.1");
        rotate(&path, &renamed, b"b1\n");
        fs::set_permissions(&renamed, fs::Permissions::from_mode(0o000)).expect("locked");
        // Permissions are not enforced as root.
        if File::open(&renamed).is_ok() {
            return;
        }
        let mut run = Run::start(&path, Options::default());
        run.resume(old);
        match run.next().await {
            Event::Problem(problem) => assert!(
                problem.reason().starts_with("cannot open the file: "),
                "{problem:?}"
            ),
            other => panic!("expected a problem, found {other:?}"),
        }
        // The path is not read from its beginning in the meantime.
        run.quiet(POLL * 3).await;

        fs::set_permissions(&renamed, fs::Permissions::from_mode(0o644)).expect("unlocked");
        assert_opened(run.next().await, old);
        assert_eq!(run.batch().await.0, ["a2"]);
        assert_opened(run.event().await, position(&path, 0));
        assert_eq!(run.batch().await.0, ["b1"]);
        assert!(
            !logs.text().contains("Cannot find the file"),
            "{}",
            logs.text()
        );
    }

    #[tokio::test]
    async fn a_directory_that_cannot_be_searched_is_searched_again() {
        let (logs, _guard) = Logs::capture();
        let (dir, path, _state) = files(b"a1\na2\n");
        let old = position(&path, 3);
        let renamed = dir.path().join("a.log.1");
        rotate(&path, &renamed, b"b1\n");
        // Listing the directory works, inspecting its entries does not.
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o400)).expect("locked");
        // Permissions are not enforced as root.
        if fs::symlink_metadata(&renamed).is_ok() {
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).expect("unlocked");
            return;
        }
        let mut run = Run::start(&path, Options::default());
        run.resume(old);
        let event = run.next().await;
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).expect("unlocked");
        match event {
            Event::Problem(problem) => assert!(
                problem.reason().starts_with("cannot inspect the path: "),
                "{problem:?}"
            ),
            other => panic!("expected a problem, found {other:?}"),
        }

        // The predecessor's suffix arrives before the current file.
        assert_opened(run.next().await, old);
        assert_eq!(run.batch().await.0, ["a2"]);
        assert_opened(run.event().await, position(&path, 0));
        assert_eq!(run.batch().await.0, ["b1"]);
        assert!(
            !logs.text().contains("Cannot find the file"),
            "{}",
            logs.text()
        );
    }

    #[tokio::test]
    async fn a_lost_predecessor_reads_the_path_from_its_beginning() {
        let (logs, _guard) = Logs::capture();
        let (_dir, path, _state) = files(b"a1\n");
        let mut run = Run::start(&path, Options::default());
        let current = position(&path, 0);
        run.resume(LogPosition {
            ino: current.ino.wrapping_add(1_000_003),
            offset: 9,
            ..current
        });
        assert_opened(run.next().await, current);
        assert_eq!(run.batch().await.0, ["a1"]);
        let text = logs.text();
        assert!(
            text.contains(&format!(
                "Cannot find the file kind_a was reading before {}; lines may have been lost",
                path.display()
            )),
            "{text}"
        );
    }

    #[tokio::test]
    async fn resumes_by_the_inode_only() {
        let (logs, _guard) = Logs::capture();
        let (_dir, path, _state) = files(b"a1\na2\n");
        let mut run = Run::start(&path, Options::default());
        let current = position(&path, 3);
        run.resume(LogPosition {
            dev: current.dev ^ 1,
            ..current
        });
        assert_opened(run.next().await, current);
        assert_eq!(run.batch().await.0, ["a2"]);
        assert!(
            logs.text().contains(&format!(
                "Resuming {} for kind_a by its inode only",
                path.display()
            )),
            "{}",
            logs.text()
        );
    }

    #[tokio::test]
    async fn a_resume_onto_a_shorter_file_is_a_truncation() {
        let (_dir, path, _state) = files(b"a1\n");
        // With no open handle.
        let mut run = Run::start(&path, Options::default());
        run.resume(position(&path, 10));
        assert_truncated(run.next().await, position(&path, 0));
        resume_at(&mut run, &path, 0).await;
        assert_eq!(run.batch().await.0, ["a1"]);
        // Through the open handle.
        run.resume(position(&path, 10));
        assert_truncated(run.next().await, position(&path, 0));
        resume_at(&mut run, &path, 0).await;
        assert_eq!(run.batch().await.0, ["a1"]);
    }

    #[tokio::test]
    async fn a_resume_discards_what_was_read_before_it() {
        let lines = numbered(0..5000, |index| format!("{index:05}"));
        let (_dir, path, _state) = files(lines.as_bytes());
        let mut run = Run::start(&path, Options::default());
        run.resume(position(&path, 0));
        let from = 4000 * 6;
        run.resume(position(&path, from));
        // Results of the first resume may still arrive; those of the second
        // start at its position.
        assert_opened(run.current().await, position(&path, from));
        let mut received = Vec::new();
        while received.len() < 1000 {
            received.extend(run.batch().await.0);
        }
        let expected = (4000..5000)
            .map(|index| format!("{index:05}"))
            .collect::<Vec<_>>();
        assert_eq!(received, expected);
    }

    #[test]
    fn the_opening_check_accepts_a_regular_file() {
        let (_dir, path, _state) = files(b"a1\n");
        let opened = open_checked(&path, &[], &Hook::default()).expect("accepted");
        assert_eq!(LogPosition::at(opened.id, 0), position(&path, 0));
        assert_eq!(opened.len, 3);
        assert_eq!(opened.real_path, fs::canonicalize(&path).expect("resolves"));
    }

    #[test]
    fn the_opening_check_refuses_a_fifo_and_a_directory() {
        let (dir, _path, _state) = files(b"");
        let fifo = dir.path().join("fifo");
        mkfifo(&fifo);
        for path in [fifo.as_path(), dir.path()] {
            assert!(matches!(
                open_checked(path, &[], &Hook::default()),
                Err(Problem::NotRegularFile)
            ));
        }
    }

    #[test]
    fn the_opening_check_catches_a_refused_ancestor_through_a_symlink() {
        let (dir, _path, _state) = files(b"");
        let refused = dir.path().join("refused");
        let inner = refused.join("inner");
        fs::create_dir_all(&inner).expect("created");
        fs::write(inner.join("key"), b"k\n").expect("written");
        let link = dir.path().join("link");
        symlink(&inner, &link).expect("linked");
        let name = refused.to_string_lossy().into_owned();
        let Err(Problem::Refused(found)) =
            open_checked(&link.join("key"), &refused_dirs(&[&name]), &Hook::default())
        else {
            panic!("refused");
        };
        assert_eq!(found, name);
    }

    #[test]
    fn an_ancestor_that_cannot_be_inspected_refuses() {
        assert!(matches!(
            check_ancestors(Path::new("/nonexistent-reproduce-dir/inner/a.log"), &[]),
            Err(Problem::Locate(_))
        ));

        let (dir, _path, _state) = files(b"");
        let locked = dir.path().join("locked");
        let inner = locked.join("inner");
        fs::create_dir_all(&inner).expect("created");
        fs::write(inner.join("a.log"), b"a\n").expect("written");
        let real = fs::canonicalize(inner.join("a.log")).expect("resolves");
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).expect("locked");
        let inspectable = fs::metadata(&inner).is_ok();
        let result = check_ancestors(&real, &[]);
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o700)).expect("unlocked");
        // Permissions are not enforced as root.
        if !inspectable {
            assert!(matches!(result, Err(Problem::Locate(_))), "{result:?}");
        }
    }

    #[test]
    fn an_absent_refused_directory_is_skipped() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let present = dir.path().to_string_lossy().into_owned();
        let refused = refused_dirs(&["/nonexistent-reproduce-dir", present.as_str()]);
        assert_eq!(refused.len(), 1);
        assert_eq!(refused[0].name, present);
    }
}
