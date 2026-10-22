//! The checkpoints of remote-mode collectors, in the state directory.
//!
//! A log collector's checkpoint is `checkpoints/log/<kind>.json`, holding
//! the acknowledged position of its file. The rest of `checkpoints/` is left
//! to other collector types.
//!
//! The store alone encodes positions: [`Saves`] and [`run_saver`] keep,
//! compare and hand on the positions they save, and write the bytes the
//! store encoded from them.

use std::collections::HashSet;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use serde::Serialize;
use serde_json::Value;
use tokio::time::Instant;
use tracing::{debug, info, warn};

use super::acks::Acks;
use super::follow::LogPosition;
use crate::collector::POLLING_INTERVAL;

/// The least time between two periodic saves of one collector.
const SAVE_INTERVAL: Duration = Duration::from_secs(1);

/// The name of the checkpoint directory in the state directory.
const CHECKPOINTS: &str = "checkpoints";

/// The suffix of temporary files.
const TEMPORARY_SUFFIX: &str = ".json.tmp";

/// Returns the directory of log checkpoints.
fn log_dir(state_dir: &Path) -> PathBuf {
    state_dir.join(CHECKPOINTS).join("log")
}

/// Returns the checkpoint file of the log collector of `kind`.
pub(super) fn log_file(state_dir: &Path, kind: &str) -> PathBuf {
    log_dir(state_dir).join(format!("{kind}.json"))
}

#[derive(Serialize)]
struct LogRecord<'a> {
    #[serde(rename = "type")]
    record_type: &'a str,
    kind: &'a str,
    path: &'a str,
    dev: u64,
    ino: u64,
    offset: u64,
}

/// Encodes the checkpoint of the log collector of `kind` for `path`.
fn encode_log(kind: &str, path: &Path, position: &LogPosition) -> Vec<u8> {
    let path = path.to_string_lossy();
    let record = LogRecord {
        record_type: "log",
        kind,
        path: &path,
        dev: position.dev,
        ino: position.ino,
        offset: position.offset,
    };
    let mut bytes = serde_json::to_vec(&record).unwrap_or_default();
    bytes.push(b'\n');
    bytes
}

/// What loading a log checkpoint found.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Loaded {
    /// No checkpoint file.
    Missing,
    /// A record of an earlier path of the kind.
    OtherPath(String),
    /// An unusable file: `reason` names the failed check, and `end` is the
    /// end of the collector's path, if it can be inspected.
    Corrupt {
        reason: String,
        end: Option<LogPosition>,
    },
    Found(LogPosition),
}

/// Loads the checkpoint of the log collector of `kind` for `path`.
pub(super) fn load_log(state_dir: &Path, kind: &str, path: &Path) -> Loaded {
    let bytes = match fs::read(log_file(state_dir, kind)) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Loaded::Missing,
        Err(error) => return corrupt(format!("cannot be read ({error})"), path),
    };
    match decode_log(&bytes, kind, path) {
        Ok(Decoded::Position(position)) => Loaded::Found(position),
        Ok(Decoded::OtherPath(recorded)) => Loaded::OtherPath(recorded),
        Err(reason) => corrupt(reason, path),
    }
}

fn corrupt(reason: String, path: &Path) -> Loaded {
    let end = fs::metadata(path)
        .ok()
        .map(|metadata| LogPosition::new(&metadata, metadata.len()));
    Loaded::Corrupt { reason, end }
}

#[derive(Debug, PartialEq, Eq)]
enum Decoded {
    Position(LogPosition),
    OtherPath(String),
}

/// Decodes a log record, or returns which check it fails.
fn decode_log(bytes: &[u8], kind: &str, path: &Path) -> Result<Decoded, String> {
    let value = serde_json::from_slice::<Value>(bytes).map_err(|_| "not valid JSON".to_string())?;
    let Value::Object(record) = value else {
        return Err("not a JSON object".to_string());
    };
    let field = |name: &str| {
        record
            .get(name)
            .ok_or_else(|| format!("missing field {name}"))
    };
    let string = |name: &str| {
        field(name)?
            .as_str()
            .ok_or_else(|| format!("field {name} is not a string"))
    };
    let integer = |name: &str| {
        field(name)?
            .as_u64()
            .ok_or_else(|| format!("field {name} is not a non-negative integer"))
    };
    if field("type")?.as_str() != Some("log") {
        return Err("type is not log".to_string());
    }
    let recorded_kind = string("kind")?;
    let recorded_path = string("path")?;
    let position = LogPosition {
        dev: integer("dev")?,
        ino: integer("ino")?,
        offset: integer("offset")?,
    };
    if recorded_kind != kind {
        return Err("kind does not match".to_string());
    }
    if Path::new(recorded_path).as_os_str() != path.as_os_str() {
        return Ok(Decoded::OtherPath(recorded_path.to_string()));
    }
    Ok(Decoded::Position(position))
}

/// Adds what failed to an I/O error.
fn step(what: &str, path: &Path) -> impl FnOnce(io::Error) -> io::Error {
    let context = format!("cannot {what} {}", path.display());
    move |error| io::Error::new(error.kind(), format!("{context}: {error}"))
}

/// Creates `dir` with mode 0700 if it is missing, and then syncs its
/// parent. An existing `dir` is taken as durable only if `durable`: it may
/// have been created by a save whose sync of the parent failed or is still
/// running, so its parent is synced again.
fn ensure_dir(dir: &Path, durable: bool) -> io::Result<()> {
    let mut builder = DirBuilder::new();
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    match builder.create(dir) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists && durable => return Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(step("create", dir)(error)),
    }
    if let Some(parent) = dir.parent() {
        sync_dir(parent)?;
    }
    Ok(())
}

fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)
        .and_then(|dir| dir.sync_all())
        .map_err(step("sync", dir))
}

/// Replaces `file` with `bytes` through `tmp`, durably. `dirs_durable`
/// tells whether `dirs` were all confirmed durable before, and is set once
/// they are.
fn write_atomically(
    dirs: &[PathBuf],
    dirs_durable: &AtomicBool,
    tmp: &Path,
    file: &Path,
    bytes: &[u8],
) -> io::Result<()> {
    let durable = dirs_durable.load(Ordering::SeqCst);
    for dir in dirs {
        ensure_dir(dir, durable)?;
    }
    dirs_durable.store(true, Ordering::SeqCst);
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut temporary = options.open(tmp).map_err(step("create", tmp))?;
    temporary.write_all(bytes).map_err(step("write", tmp))?;
    temporary.sync_all().map_err(step("sync", tmp))?;
    drop(temporary);
    fs::rename(tmp, file).map_err(step("rename", tmp))?;
    if let Some(dir) = dirs.last() {
        sync_dir(dir)?;
    }
    Ok(())
}

/// Deletes every entry named `*.json.tmp` that is not a directory in
/// `checkpoints/` and its subdirectories, never following a symbolic link.
pub(super) fn remove_temporary_files(state_dir: &Path) {
    let root = state_dir.join(CHECKPOINTS);
    match fs::symlink_metadata(&root) {
        Ok(metadata) if metadata.is_dir() => remove_temporary_files_in(&root),
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => warn!("Cannot read the directory {}: {error}", root.display()),
    }
}

fn remove_temporary_files_in(dir: &Path) {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) => {
            warn!("Cannot read the directory {}: {error}", dir.display());
            return;
        }
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                warn!("Cannot read the directory {}: {error}", dir.display());
                return;
            }
        };
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(error) => {
                warn!("Cannot read the directory {}: {error}", dir.display());
                continue;
            }
        };
        if file_type.is_dir() {
            remove_temporary_files_in(&path);
        } else if entry
            .file_name()
            .as_encoded_bytes()
            .ends_with(TEMPORARY_SUFFIX.as_bytes())
        {
            match fs::remove_file(&path) {
                Ok(()) => debug!("Deleted the temporary file {}", path.display()),
                Err(error) => warn!("Cannot delete {}: {error}", path.display()),
            }
        }
    }
}

/// What deleting the files of unconfigured kinds did, to be logged where
/// the deletion was requested.
#[derive(Debug)]
pub(super) enum Deletion {
    Checkpoint(String),
    Temporary(PathBuf),
    Failed(PathBuf, io::Error),
    Unreadable(PathBuf, io::Error),
}

impl Deletion {
    pub(super) fn log(&self) {
        match self {
            Self::Checkpoint(kind) => info!("Deleted the checkpoint of {kind}"),
            Self::Temporary(path) => debug!("Deleted the temporary file {}", path.display()),
            Self::Failed(path, error) => warn!("Cannot delete {}: {error}", path.display()),
            Self::Unreadable(path, error) => {
                warn!("Cannot read the directory {}: {error}", path.display());
            }
        }
    }
}

/// Deletes every regular file or symbolic link in `checkpoints/log/` named
/// `<k>.json` or `<k>.json.tmp` whose `<k>` is not one of `kinds`.
pub(super) fn delete_unconfigured(state_dir: &Path, kinds: &HashSet<String>) -> Vec<Deletion> {
    let dir = log_dir(state_dir);
    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Vec::new(),
        Err(error) => return vec![Deletion::Unreadable(dir, error)],
    };
    let mut deletions = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                deletions.push(Deletion::Unreadable(dir.clone(), error));
                break;
            }
        };
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_file() && !file_type.is_symlink() {
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let (kind, temporary) = if let Some(kind) = name.strip_suffix(TEMPORARY_SUFFIX) {
            (kind, true)
        } else if let Some(kind) = name.strip_suffix(".json") {
            (kind, false)
        } else {
            continue;
        };
        if kinds.contains(kind) {
            continue;
        }
        let path = entry.path();
        deletions.push(match fs::remove_file(&path) {
            Ok(()) if temporary => Deletion::Temporary(path),
            Ok(()) => Deletion::Checkpoint(kind.to_string()),
            Err(error) => Deletion::Failed(path, error),
        });
    }
    deletions
}

/// How a save ended.
#[derive(Debug)]
pub(super) enum Outcome {
    Landed,
    /// A save requested later has already landed.
    Superseded,
    /// A save requested later has already been attempted but has not
    /// landed: this one is obsolete, and nothing is saved.
    Overtaken,
    /// The save state is retired: nothing lands any more.
    Retired,
    Failed(io::Error),
}

impl Outcome {
    /// Returns whether the position, or a later one, is saved.
    pub(super) fn saved(&self) -> bool {
        matches!(self, Self::Landed | Self::Superseded)
    }
}

type Encode<P> = Box<dyn Fn(&P) -> Vec<u8> + Send + Sync>;

/// The save state of one collector: its saves land in the order they were
/// requested, and none lands once it is retired.
pub(super) struct Saves<P> {
    kind: String,
    /// The directories to create, outermost first; the last one holds the
    /// file.
    dirs: Vec<PathBuf>,
    file: PathBuf,
    tmp: PathBuf,
    encode: Encode<P>,
    /// Held across every write to the file, by every collector of the kind.
    lock: Arc<Mutex<()>>,
    /// The sequence number of the last save requested.
    requested: AtomicU64,
    /// The sequence number of the last save attempted; changed under
    /// `lock`.
    attempted: AtomicU64,
    /// The sequence number of the last save landed; changed under `lock`.
    landed: AtomicU64,
    /// Whether this state has confirmed its directories durable.
    dirs_durable: AtomicBool,
    retired: AtomicBool,
    /// Whether the last save failed, for logging.
    failing: AtomicBool,
    writes: AtomicU64,
}

impl Saves<LogPosition> {
    /// Returns the save state of the log collector of `kind` for `path`.
    /// `lock` is shared by every collector of the kind.
    pub(super) fn log(state_dir: &Path, kind: &str, path: &Path, lock: Arc<Mutex<()>>) -> Self {
        let dir = log_dir(state_dir);
        let encode = {
            let kind = kind.to_string();
            let path = path.to_path_buf();
            Box::new(move |position: &LogPosition| encode_log(&kind, &path, position))
        };
        Self {
            kind: kind.to_string(),
            dirs: vec![state_dir.join(CHECKPOINTS), dir.clone()],
            file: dir.join(format!("{kind}.json")),
            tmp: dir.join(format!("{kind}{TEMPORARY_SUFFIX}")),
            encode,
            lock,
            requested: AtomicU64::new(0),
            attempted: AtomicU64::new(0),
            landed: AtomicU64::new(0),
            dirs_durable: AtomicBool::new(false),
            retired: AtomicBool::new(false),
            failing: AtomicBool::new(false),
            writes: AtomicU64::new(0),
        }
    }
}

impl<P: Send + Sync + 'static> Saves<P> {
    /// Saves `position`, logging a failure when the state changes.
    pub(super) async fn save(self: &Arc<Self>, position: &P) -> Outcome {
        self.save_as(self.request(), position).await
    }

    /// Saves `position` as the save numbered `sequence`, which
    /// [`request`](Self::request) returned, logging a failure when the state
    /// changes.
    async fn save_as(self: &Arc<Self>, sequence: u64, position: &P) -> Outcome {
        let outcome = self.write(sequence, position, false).await;
        match &outcome {
            Outcome::Landed => {
                debug!(
                    "Saved the checkpoint of {} to {}",
                    self.kind,
                    self.file.display()
                );
                if self.failing.swap(false, Ordering::Relaxed) {
                    info!("Saved the checkpoint of {} again", self.kind);
                }
            }
            Outcome::Failed(error) => {
                if self.failing.swap(true, Ordering::Relaxed) {
                    debug!(
                        "Still cannot save the checkpoint of {} to {}: {error}",
                        self.kind,
                        self.file.display()
                    );
                } else {
                    warn!(
                        "Cannot save the checkpoint of {} to {}: {error}; retrying every {POLLING_INTERVAL:?}",
                        self.kind,
                        self.file.display()
                    );
                }
            }
            Outcome::Superseded | Outcome::Overtaken | Outcome::Retired => {}
        }
        outcome
    }

    /// Makes the last save, of `position` if there is one, superseding any
    /// pending or failing save, and retires the save state.
    pub(super) async fn final_save(self: &Arc<Self>, position: Option<&P>) {
        let outcome = if let Some(position) = position {
            self.write(self.request(), position, true).await
        } else {
            self.retire();
            self.settle().await;
            Outcome::Retired
        };
        match outcome {
            Outcome::Landed => debug!(
                "Saved the checkpoint of {} to {}",
                self.kind,
                self.file.display()
            ),
            Outcome::Failed(error) => {
                warn!(
                    "Cannot save the checkpoint of {} at stop: {error}",
                    self.kind
                );
            }
            Outcome::Superseded | Outcome::Overtaken | Outcome::Retired => {}
        }
    }

    /// Retires the save state: no save lands after a write already in
    /// progress, which [`settle`](Self::settle) waits for.
    pub(super) fn retire(&self) {
        self.retired.store(true, Ordering::SeqCst);
    }

    /// Waits for a write in progress to end.
    pub(super) async fn settle(self: &Arc<Self>) {
        let this = Arc::clone(self);
        let _ = tokio::task::spawn_blocking(move || {
            drop(this.lock.lock().unwrap_or_else(PoisonError::into_inner));
        })
        .await;
    }

    /// Returns the number of writes that landed.
    #[cfg(test)]
    pub(super) fn writes(&self) -> u64 {
        self.writes.load(Ordering::SeqCst)
    }

    fn request(&self) -> u64 {
        self.requested.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// Writes `position` as the save numbered `sequence`, unless the state
    /// is retired or a later save has been attempted; `last` retires the
    /// state with this write, even one that is superseded or fails.
    async fn write(self: &Arc<Self>, sequence: u64, position: &P, last: bool) -> Outcome {
        let bytes = (self.encode)(position);
        let this = Arc::clone(self);
        tokio::task::spawn_blocking(move || this.write_blocking(sequence, &bytes, last))
            .await
            .unwrap_or_else(|error| Outcome::Failed(io::Error::other(error)))
    }

    fn write_blocking(&self, sequence: u64, bytes: &[u8], last: bool) -> Outcome {
        let _guard = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
        if self.retired.load(Ordering::SeqCst) {
            return Outcome::Retired;
        }
        // Under the lock, so no other write sees it before this one ends.
        if last {
            self.retire();
        }
        if self.landed.load(Ordering::SeqCst) > sequence {
            return Outcome::Superseded;
        }
        // A later save that failed still supersedes this one, but does not
        // make it saved.
        if self.attempted.load(Ordering::SeqCst) > sequence {
            return Outcome::Overtaken;
        }
        self.attempted.store(sequence, Ordering::SeqCst);
        match write_atomically(&self.dirs, &self.dirs_durable, &self.tmp, &self.file, bytes) {
            Ok(()) => {
                self.landed.store(sequence, Ordering::SeqCst);
                self.writes.fetch_add(1, Ordering::SeqCst);
                Outcome::Landed
            }
            Err(error) => Outcome::Failed(error),
        }
    }
}

/// Sets the starting position of a collector: drops its queued entries and
/// sets its acknowledged position to `position` in one step, then saves it
/// at once. The save lands after every save requested before it; a failure
/// leaves retrying to the caller.
pub(super) async fn start_at<P>(acks: &Acks<P>, saves: &Arc<Saves<P>>, position: P) -> Outcome
where
    P: Clone + PartialEq + Send + Sync + 'static,
{
    acks.start(position.clone());
    saves.save(&position).await
}

/// Saves a collector's acknowledged position whenever it changes, at most
/// once per [`SAVE_INTERVAL`] and no later than [`SAVE_INTERVAL`] after it
/// changed. A failed save is retried after [`POLLING_INTERVAL`] with the
/// then-latest position. Ends once the save state is retired.
pub(super) async fn run_saver<P>(acks: Arc<Acks<P>>, saves: Arc<Saves<P>>)
where
    P: Clone + PartialEq + Send + Sync + 'static,
{
    // The loaded checkpoint, version 0, is already saved.
    let mut saved_version = 0;
    let mut last_write: Option<Instant> = None;
    loop {
        while acks.version() == saved_version {
            acks.changed().await;
        }
        if let Some(last_write) = last_write {
            tokio::time::sleep_until(last_write + SAVE_INTERVAL).await;
        }
        // Requested before the snapshot, so a save requested after it, such
        // as a starting position's, is never overwritten by an older
        // position.
        let sequence = saves.request();
        let (version, position) = acks.snapshot();
        let Some(position) = position else {
            saved_version = version;
            continue;
        };
        last_write = Some(Instant::now());
        match saves.save_as(sequence, &position).await {
            outcome if outcome.saved() => saved_version = version,
            Outcome::Retired => return,
            _ => tokio::time::sleep(POLLING_INTERVAL).await,
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::{PermissionsExt, symlink};

    use tempfile::TempDir;

    use super::*;

    const KIND: &str = "kind_a";

    /// Time allowed for scheduling and a write's `fsync`s on a busy machine.
    const MARGIN: Duration = Duration::from_millis(500);

    fn position(offset: u64) -> LogPosition {
        LogPosition {
            dev: 1,
            ino: 2,
            offset,
        }
    }

    fn saves(state: &TempDir, path: &Path) -> Arc<Saves<LogPosition>> {
        Arc::new(Saves::log(
            state.path(),
            KIND,
            path,
            Arc::new(Mutex::new(())),
        ))
    }

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).expect("metadata").permissions().mode() & 0o777
    }

    #[test]
    fn encodes_and_decodes_the_exact_record() {
        let path = Path::new("/var/log/a.log");
        let bytes = encode_log(KIND, path, &position(42));
        assert_eq!(
            String::from_utf8(bytes.clone()).expect("UTF-8"),
            "{\"type\":\"log\",\"kind\":\"kind_a\",\"path\":\"/var/log/a.log\",\
             \"dev\":1,\"ino\":2,\"offset\":42}\n"
        );
        assert_eq!(
            decode_log(&bytes, KIND, path),
            Ok(Decoded::Position(position(42)))
        );
        // Unknown extra fields are ignored.
        let extra = br#"{"type":"log","kind":"kind_a","path":"/var/log/a.log","dev":1,"ino":2,"offset":42,"x":true}"#;
        assert_eq!(
            decode_log(extra, KIND, path),
            Ok(Decoded::Position(position(42)))
        );
    }

    #[test]
    fn rejects_records_failing_a_check() {
        let path = Path::new("/a.log");
        let cases: &[(&[u8], &str)] = &[
            (b"{", "not valid JSON"),
            (b"[1]", "not a JSON object"),
            (
                br#"{"kind":"kind_a","path":"/a.log","dev":1,"ino":2,"offset":3}"#,
                "missing field type",
            ),
            (
                br#"{"type":"journal","kind":"kind_a","path":"/a.log","dev":1,"ino":2,"offset":3}"#,
                "type is not log",
            ),
            (
                br#"{"type":"log","kind":"other","path":"/a.log","dev":1,"ino":2,"offset":3}"#,
                "kind does not match",
            ),
            (
                br#"{"type":"log","kind":"kind_a","path":"/a.log","ino":2,"offset":3}"#,
                "missing field dev",
            ),
            (
                br#"{"type":"log","kind":"kind_a","path":"/a.log","dev":1,"ino":-2,"offset":3}"#,
                "field ino is not a non-negative integer",
            ),
            (
                br#"{"type":"log","kind":"kind_a","path":7,"dev":1,"ino":2,"offset":3}"#,
                "field path is not a string",
            ),
            (
                br#"{"type":"log","kind":"kind_a","path":"/a.log","dev":1,"ino":2,"offset":"3"}"#,
                "field offset is not a non-negative integer",
            ),
        ];
        for (bytes, reason) in cases {
            assert_eq!(
                decode_log(bytes, KIND, path),
                Err((*reason).to_string()),
                "{}",
                String::from_utf8_lossy(bytes)
            );
        }
    }

    #[test]
    fn loads_missing_other_path_and_corrupt_files() -> anyhow::Result<()> {
        let state = tempfile::tempdir()?;
        let logs = tempfile::tempdir()?;
        let path = logs.path().join("a.log");
        fs::write(&path, b"one\ntwo\n")?;
        let metadata = fs::metadata(&path)?;
        let end = Some(LogPosition::new(&metadata, 8));

        assert_eq!(load_log(state.path(), KIND, &path), Loaded::Missing);

        fs::create_dir_all(log_dir(state.path()))?;
        let file = log_file(state.path(), KIND);
        fs::write(&file, encode_log(KIND, Path::new("/old.log"), &position(3)))?;
        assert_eq!(
            load_log(state.path(), KIND, &path),
            Loaded::OtherPath("/old.log".to_string())
        );

        fs::write(&file, encode_log(KIND, &path, &position(3)))?;
        assert_eq!(
            load_log(state.path(), KIND, &path),
            Loaded::Found(position(3))
        );

        for (bytes, reason) in [
            (&b"not json"[..], "not valid JSON"),
            (
                br#"{"kind":"kind_a","path":"x","dev":1,"ino":2,"offset":3}"#,
                "missing field type",
            ),
            (
                br#"{"type":"journal","kind":"kind_a","path":"x","dev":1,"ino":2,"offset":3}"#,
                "type is not log",
            ),
        ] {
            fs::write(&file, bytes)?;
            assert_eq!(
                load_log(state.path(), KIND, &path),
                Loaded::Corrupt {
                    reason: reason.to_string(),
                    end
                }
            );
            // When the path cannot be inspected, there is no position.
            assert_eq!(
                load_log(state.path(), KIND, &logs.path().join("missing.log")),
                Loaded::Corrupt {
                    reason: reason.to_string(),
                    end: None
                }
            );
        }

        // An unreadable file, here a directory in its place.
        fs::remove_file(&file)?;
        fs::create_dir(&file)?;
        let Loaded::Corrupt { reason, end: found } = load_log(state.path(), KIND, &path) else {
            panic!("an unreadable file is corrupt");
        };
        assert!(reason.starts_with("cannot be read"), "{reason}");
        assert_eq!(found, end);
        Ok(())
    }

    #[test]
    fn loads_a_mismatched_or_incomplete_record_as_corrupt() -> anyhow::Result<()> {
        let state = tempfile::tempdir()?;
        let logs = tempfile::tempdir()?;
        let path = logs.path().join("a.log");
        fs::write(&path, b"one\ntwo\nthree\n")?;
        let metadata = fs::metadata(&path)?;
        let end = LogPosition::new(&metadata, metadata.len());
        // The fallback is the log's actual device, inode and length.
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(
                (end.dev, end.ino, end.offset),
                (metadata.dev(), metadata.ino(), 14)
            );
        }
        let missing = logs.path().join("missing.log");
        fs::create_dir_all(log_dir(state.path()))?;
        let file = log_file(state.path(), KIND);

        for (record, reason) in [
            (
                encode_log("other", &path, &position(3)),
                "kind does not match",
            ),
            (
                format!(
                    "{{\"type\":\"log\",\"kind\":\"{KIND}\",\"path\":\"{}\",\"ino\":2,\"offset\":3}}",
                    path.display()
                )
                .into_bytes(),
                "missing field dev",
            ),
        ] {
            fs::write(&file, &record)?;
            assert_eq!(
                load_log(state.path(), KIND, &path),
                Loaded::Corrupt {
                    reason: reason.to_string(),
                    end: Some(end),
                }
            );
            // The record names the missing path, so only the missing log
            // decides the fallback.
            let record = String::from_utf8(record)?.replace(
                &path.display().to_string(),
                &missing.display().to_string(),
            );
            fs::write(&file, record)?;
            assert_eq!(
                load_log(state.path(), KIND, &missing),
                Loaded::Corrupt {
                    reason: reason.to_string(),
                    end: None,
                }
            );
        }

        // An unreadable file, here a directory in its place, with a missing
        // log.
        fs::remove_file(&file)?;
        fs::create_dir(&file)?;
        let Loaded::Corrupt { reason, end } = load_log(state.path(), KIND, &missing) else {
            panic!("an unreadable file is corrupt");
        };
        assert!(reason.starts_with("cannot be read"), "{reason}");
        assert_eq!(end, None);
        Ok(())
    }

    #[tokio::test]
    async fn saves_create_the_directories_and_files_privately() -> anyhow::Result<()> {
        let state = tempfile::tempdir()?;
        let path = Path::new("/a.log");
        let saves = saves(&state, path);
        assert!(saves.save(&position(5)).await.saved());

        let file = log_file(state.path(), KIND);
        assert_eq!(fs::read(&file)?, encode_log(KIND, path, &position(5)));
        assert_eq!(mode(&state.path().join(CHECKPOINTS)), 0o700);
        assert_eq!(mode(&log_dir(state.path())), 0o700);
        assert_eq!(mode(&file), 0o600);
        assert!(!log_dir(state.path()).join("kind_a.json.tmp").exists());
        assert_eq!(saves.writes(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn a_partial_temporary_file_leaves_the_checkpoint_intact() -> anyhow::Result<()> {
        let state = tempfile::tempdir()?;
        let logs = tempfile::tempdir()?;
        let path = logs.path().join("a.log");
        fs::write(&path, b"x\n")?;
        let saves = saves(&state, &path);
        assert!(saves.save(&position(9)).await.saved());
        // An interrupted save left half a record behind.
        fs::write(
            log_dir(state.path()).join("kind_a.json.tmp"),
            b"{\"type\":\"lo",
        )?;
        assert_eq!(
            load_log(state.path(), KIND, &path),
            Loaded::Found(position(9))
        );
        // The next save replaces it.
        assert!(saves.save(&position(10)).await.saved());
        assert_eq!(
            load_log(state.path(), KIND, &path),
            Loaded::Found(position(10))
        );
        Ok(())
    }

    #[tokio::test]
    async fn an_earlier_save_never_overwrites_a_later_one() -> anyhow::Result<()> {
        let state = tempfile::tempdir()?;
        let path = Path::new("/a.log");
        let saves = saves(&state, path);
        let earlier = saves.request();
        let later = saves.request();
        assert!(matches!(
            saves.write(later, &position(2), false).await,
            Outcome::Landed
        ));
        assert!(matches!(
            saves.write(earlier, &position(1), false).await,
            Outcome::Superseded
        ));
        assert_eq!(
            fs::read(log_file(state.path(), KIND))?,
            encode_log(KIND, path, &position(2))
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_failing_save_recovers_and_is_superseded() -> anyhow::Result<()> {
        let state = tempfile::tempdir()?;
        let path = Path::new("/a.log");
        let saves = saves(&state, path);
        let tmp = log_dir(state.path()).join("kind_a.json.tmp");
        fs::create_dir_all(&tmp)?;
        assert!(matches!(saves.save(&position(1)).await, Outcome::Failed(_)));
        assert!(matches!(saves.save(&position(2)).await, Outcome::Failed(_)));
        assert!(!log_file(state.path(), KIND).exists());
        assert_eq!(saves.writes(), 0);

        fs::remove_dir(&tmp)?;
        assert!(saves.save(&position(3)).await.saved());
        assert_eq!(
            fs::read(log_file(state.path(), KIND))?,
            encode_log(KIND, path, &position(3))
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_failing_later_save_supersedes_a_pending_one() -> anyhow::Result<()> {
        let state = tempfile::tempdir()?;
        let path = Path::new("/a.log");
        let saves = saves(&state, path);
        assert!(saves.save(&position(1)).await.saved());
        let pending = saves.request();
        let later = saves.request();
        let tmp = log_dir(state.path()).join("kind_a.json.tmp");
        fs::create_dir(&tmp)?;
        assert!(matches!(
            saves.write(later, &position(3), false).await,
            Outcome::Failed(_)
        ));
        fs::remove_dir(&tmp)?;

        // The pending save is obsolete, and is not reported as saved.
        let outcome = saves.write(pending, &position(2), false).await;
        assert!(matches!(outcome, Outcome::Overtaken), "{outcome:?}");
        assert!(!outcome.saved());
        assert_eq!(
            fs::read(log_file(state.path(), KIND))?,
            encode_log(KIND, path, &position(1))
        );
        assert!(saves.save(&position(4)).await.saved());
        assert_eq!(
            fs::read(log_file(state.path(), KIND))?,
            encode_log(KIND, path, &position(4))
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_directory_counts_only_once_its_parent_is_synced() -> anyhow::Result<()> {
        let state = tempfile::tempdir()?;
        let path = Path::new("/a.log");
        // Without read permission, the state directory can gain entries but
        // cannot be opened to be synced.
        fs::set_permissions(state.path(), fs::Permissions::from_mode(0o300))?;
        if File::open(state.path()).is_ok() {
            // Permissions are not enforced (for example, as root).
            fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700))?;
            return Ok(());
        }
        let saves = saves(&state, path);
        let outcome = saves.save(&position(1)).await;
        assert!(matches!(outcome, Outcome::Failed(_)), "{outcome:?}");
        assert!(state.path().join(CHECKPOINTS).is_dir());

        // The directory now exists, but its entry is still not durable: a
        // retry, or another collector's save, syncs the parent again.
        let outcome = saves.save(&position(2)).await;
        assert!(matches!(outcome, Outcome::Failed(_)), "{outcome:?}");
        let other = self::saves(&state, path);
        let outcome = other.save(&position(2)).await;
        assert!(matches!(outcome, Outcome::Failed(_)), "{outcome:?}");
        assert!(!log_file(state.path(), KIND).exists());

        fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700))?;
        assert!(saves.save(&position(3)).await.saved());
        assert_eq!(
            fs::read(log_file(state.path(), KIND))?,
            encode_log(KIND, path, &position(3))
        );
        assert_eq!(saves.writes(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn a_retired_save_state_lands_nothing() -> anyhow::Result<()> {
        let state = tempfile::tempdir()?;
        let path = Path::new("/a.log");
        let saves = saves(&state, path);
        assert!(saves.save(&position(1)).await.saved());
        saves.retire();
        saves.settle().await;
        assert!(matches!(saves.save(&position(2)).await, Outcome::Retired));
        saves.final_save(Some(&position(3))).await;
        assert_eq!(
            fs::read(log_file(state.path(), KIND))?,
            encode_log(KIND, path, &position(1))
        );
        Ok(())
    }

    #[tokio::test]
    async fn the_final_save_is_the_last() -> anyhow::Result<()> {
        let state = tempfile::tempdir()?;
        let path = Path::new("/a.log");
        let saves = saves(&state, path);
        let pending = saves.request();
        saves.final_save(Some(&position(7))).await;
        assert!(matches!(
            saves.write(pending, &position(1), false).await,
            Outcome::Retired
        ));
        assert!(matches!(saves.save(&position(8)).await, Outcome::Retired));
        assert_eq!(
            fs::read(log_file(state.path(), KIND))?,
            encode_log(KIND, path, &position(7))
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_superseded_final_save_still_retires() -> anyhow::Result<()> {
        let state = tempfile::tempdir()?;
        let path = Path::new("/a.log");
        let saves = saves(&state, path);
        let last = saves.request();
        let later = saves.request();
        assert!(matches!(
            saves.write(later, &position(2), false).await,
            Outcome::Landed
        ));
        assert!(matches!(
            saves.write(last, &position(1), true).await,
            Outcome::Superseded
        ));
        assert!(matches!(saves.save(&position(3)).await, Outcome::Retired));
        assert_eq!(
            fs::read(log_file(state.path(), KIND))?,
            encode_log(KIND, path, &position(2))
        );
        Ok(())
    }

    #[tokio::test]
    async fn periodic_saves_are_throttled() -> anyhow::Result<()> {
        let state = tempfile::tempdir()?;
        let path = Path::new("/a.log");
        let saves = saves(&state, path);
        let acks = Arc::new(Acks::new());
        acks.replace(true);
        let task = tokio::spawn(run_saver(Arc::clone(&acks), Arc::clone(&saves)));
        let read = || load_log(state.path(), KIND, path);

        // The first change is written at once.
        let opened = Instant::now();
        acks.opened(position(0));
        while saves.writes() < 1 {
            assert!(opened.elapsed() < MARGIN, "written late");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(read(), Loaded::Found(position(0)));

        // Several changes within a second cost one write, no later than a
        // second after the last one.
        let started = Instant::now();
        for offset in 1..=4 {
            acks.consumed(position(offset));
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let changed = Instant::now();
        while saves.writes() < 2 {
            assert!(changed.elapsed() < SAVE_INTERVAL + MARGIN, "written late");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(read(), Loaded::Found(position(4)));
        tokio::time::sleep(Duration::from_millis(1200)).await;
        assert_eq!(saves.writes(), 2, "{:?}", started.elapsed());

        // A starting position is written at once, outside the throttle: the
        // saver has just written and waits a second before its next write.
        acks.consumed(position(5));
        while saves.writes() < 3 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(start_at(&acks, &saves, position(100)).await.saved());
        assert_eq!(saves.writes(), 4);
        assert_eq!(read(), Loaded::Found(position(100)));

        saves.retire();
        acks.consumed(position(101));
        tokio::time::timeout(Duration::from_secs(5), task).await??;
        Ok(())
    }

    #[test]
    fn startup_removes_temporary_files_only() -> anyhow::Result<()> {
        let state = tempfile::tempdir()?;
        let outside = tempfile::tempdir()?;
        let checkpoints = state.path().join(CHECKPOINTS);
        let log = log_dir(state.path());
        fs::create_dir_all(&log)?;
        fs::write(checkpoints.join("journal.json.tmp"), b"x")?;
        fs::write(checkpoints.join("journal.json"), b"x")?;
        fs::write(log.join("a.json.tmp"), b"x")?;
        fs::write(log.join("a.json"), b"x")?;
        let target = outside.path().join("target.json.tmp");
        fs::write(&target, b"x")?;
        symlink(&target, log.join("x.json.tmp"))?;
        fs::create_dir(log.join("y.json.tmp"))?;
        fs::write(log.join("y.json.tmp").join("z.json.tmp"), b"x")?;

        remove_temporary_files(state.path());

        assert!(!checkpoints.join("journal.json.tmp").exists());
        assert!(checkpoints.join("journal.json").exists());
        assert!(!log.join("a.json.tmp").exists());
        assert!(log.join("a.json").exists());
        assert!(fs::symlink_metadata(log.join("x.json.tmp")).is_err());
        assert!(target.exists(), "a link's target is untouched");
        assert!(log.join("y.json.tmp").is_dir());
        assert!(!log.join("y.json.tmp").join("z.json.tmp").exists());
        Ok(())
    }

    #[test]
    fn startup_cleanup_does_not_follow_a_linked_checkpoints_directory() -> anyhow::Result<()> {
        let state = tempfile::tempdir()?;
        let outside = tempfile::tempdir()?;
        fs::write(outside.path().join("a.json.tmp"), b"x")?;
        symlink(outside.path(), state.path().join(CHECKPOINTS))?;
        remove_temporary_files(state.path());
        assert!(outside.path().join("a.json.tmp").exists());

        // A missing directory is not an error.
        let empty = tempfile::tempdir()?;
        remove_temporary_files(empty.path());
        Ok(())
    }

    #[test]
    fn apply_deletes_the_files_of_unconfigured_kinds() -> anyhow::Result<()> {
        let state = tempfile::tempdir()?;
        let checkpoints = state.path().join(CHECKPOINTS);
        let log = log_dir(state.path());
        fs::create_dir_all(&log)?;
        for name in [
            "gone.json",
            "gone.json.tmp",
            "a.json.json",
            "kept.json",
            "kept.json.tmp",
            "notes.txt",
        ] {
            fs::write(log.join(name), b"x")?;
        }
        fs::create_dir(log.join("dir.json"))?;
        fs::write(checkpoints.join("journal.json"), b"x")?;
        fs::write(checkpoints.join("gone.json"), b"x")?;

        let kinds = HashSet::from(["kept".to_string()]);
        let mut deletions = delete_unconfigured(state.path(), &kinds)
            .iter()
            .map(|deletion| match deletion {
                Deletion::Checkpoint(kind) => format!("checkpoint {kind}"),
                Deletion::Temporary(path) => format!(
                    "temporary {}",
                    path.file_name().unwrap_or_default().to_string_lossy()
                ),
                other => format!("{other:?}"),
            })
            .collect::<Vec<_>>();
        deletions.sort();
        assert_eq!(
            deletions,
            [
                "checkpoint a.json",
                "checkpoint gone",
                "temporary gone.json.tmp"
            ]
        );
        for kept in ["kept.json", "kept.json.tmp", "notes.txt", "dir.json"] {
            assert!(log.join(kept).exists(), "{kept}");
        }
        assert!(checkpoints.join("journal.json").exists());
        assert!(checkpoints.join("gone.json").exists());

        // A missing directory deletes nothing.
        let empty = tempfile::tempdir()?;
        assert!(delete_unconfigured(empty.path(), &kinds).is_empty());
        Ok(())
    }
}
