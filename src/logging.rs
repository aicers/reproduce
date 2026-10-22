//! Logging set-up: standard output, the systemd journal, or a log file.
//!
//! Events go to standard output through a non-blocking writer. When standard
//! output or standard error is connected to the systemd journal (as
//! `JOURNAL_STREAM` says), each event is written as one line that starts with
//! its syslog priority, `<N>`, without a timestamp or ANSI escape codes and
//! with line feeds and NULs inside the event escaped, so the journal stores it
//! as one entry at the priority of its level. A panic is then logged as one
//! ERROR event instead of the standard library's message on standard error.
//!
//! [`Logging::use_log_file`] moves logging to a file, written in the file
//! format whatever `JOURNAL_STREAM` says.

use std::any::Any;
use std::ffi::OsStr;
use std::fs::OpenOptions;
use std::io::{self, IsTerminal, Write};
use std::panic::Location;
use std::path::Path;

use anyhow::{Context as _, Result};
use tracing::level_filters::LevelFilter;
use tracing::{Level, Metadata};
use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};
use tracing_subscriber::fmt::{self, MakeWriter};
use tracing_subscriber::layer::{Layered, SubscriberExt};
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer, Registry, reload};

/// The subscriber the output layer is layered upon.
type Filtered = Layered<EnvFilter, Registry>;

/// The output layer, replaced by [`Logging::use_log_file`].
type OutputLayer = Box<dyn Layer<Filtered> + Send + Sync>;

/// `st_dev` and `st_ino` of a file descriptor.
type FileId = (u64, u64);

/// The logging of the process, from [`init_tracing`].
///
/// Dropping it flushes the events written so far.
pub struct Logging {
    handle: reload::Handle<OutputLayer, Filtered>,
    guard: WorkerGuard,
    journal: bool,
}

impl Logging {
    /// Returns whether events are written to the systemd journal.
    #[must_use]
    pub fn is_journal(&self) -> bool {
        self.journal
    }

    /// Moves logging from standard output to the file at `path`.
    ///
    /// The file is created when missing and appended to. Events are written
    /// to it with a timestamp, without the target and without ANSI escape
    /// codes, whatever `JOURNAL_STREAM` says, and the default panic hook is
    /// restored.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be opened.
    pub fn use_log_file(&mut self, path: &Path) -> Result<()> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("Failed to open the log file: {}", path.display()))?;
        let (writer, guard) = tracing_appender::non_blocking(file);
        self.handle
            .reload(
                fmt::Layer::default()
                    .with_ansi(false)
                    .with_target(false)
                    .with_writer(writer)
                    .boxed(),
            )
            .context("cannot move logging to the log file")?;
        // Dropping the standard-output guard flushes what was written there.
        self.guard = guard;
        if self.journal {
            drop(std::panic::take_hook());
            self.journal = false;
        }
        Ok(())
    }
}

/// Initializes logging to standard output.
///
/// Events at INFO and above are written unless `RUST_LOG` says otherwise.
/// When the output is the systemd journal, events are written in the journal
/// format and a panic hook that logs a panic as one ERROR event is installed;
/// otherwise events are written with a timestamp, with ANSI escape codes only
/// when standard output is a terminal. Nothing is logged here.
///
/// # Errors
///
/// Returns an error if a global subscriber is already set.
pub fn init_tracing() -> Result<Logging> {
    let journal = is_journal(
        std::env::var_os("JOURNAL_STREAM").as_deref(),
        stdout_id(),
        stderr_id(),
    );
    let (writer, guard) = tracing_appender::non_blocking(io::stdout());
    let layer: OutputLayer = if journal {
        fmt::Layer::default()
            .without_time()
            .with_ansi(false)
            .with_writer(JournalMakeWriter(writer))
            .boxed()
    } else {
        fmt::Layer::default()
            .with_ansi(io::stdout().is_terminal())
            .with_writer(writer)
            .boxed()
    };
    let (layer, handle) = reload::Layer::new(layer);
    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();
    Registry::default()
        .with(env_filter)
        .with(layer)
        .try_init()
        .context("cannot initialize logging")?;
    if journal {
        install_journal_panic_hook();
    }
    Ok(Logging {
        handle,
        guard,
        journal,
    })
}

/// Returns whether the output is the systemd journal: `JOURNAL_STREAM` is
/// `<dev>:<ino>` and names standard output or standard error.
fn is_journal(
    journal_stream: Option<&OsStr>,
    stdout: Option<FileId>,
    stderr: Option<FileId>,
) -> bool {
    let Some((dev, ino)) = journal_stream
        .and_then(OsStr::to_str)
        .and_then(|value| value.split_once(':'))
    else {
        return false;
    };
    let (Some(dev), Some(ino)) = (parse_decimal(dev), parse_decimal(ino)) else {
        return false;
    };
    let stream = Some((dev, ino));
    stdout == stream || stderr == stream
}

fn parse_decimal(value: &str) -> Option<u64> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

#[cfg(unix)]
fn stdout_id() -> Option<FileId> {
    use std::os::fd::AsFd;
    file_id(io::stdout().as_fd())
}

#[cfg(unix)]
fn stderr_id() -> Option<FileId> {
    use std::os::fd::AsFd;
    file_id(io::stderr().as_fd())
}

/// Returns `st_dev` and `st_ino` of `fd`, through a duplicate of it that is
/// closed again.
#[cfg(unix)]
fn file_id(fd: std::os::fd::BorrowedFd<'_>) -> Option<FileId> {
    use std::os::unix::fs::MetadataExt;
    let file = std::fs::File::from(fd.try_clone_to_owned().ok()?);
    let metadata = file.metadata().ok()?;
    Some((metadata.dev(), metadata.ino()))
}

#[cfg(not(unix))]
fn stdout_id() -> Option<FileId> {
    None
}

#[cfg(not(unix))]
fn stderr_id() -> Option<FileId> {
    None
}

/// The syslog priority of a level.
fn priority(level: Level) -> u8 {
    match level {
        Level::ERROR => 3,
        Level::WARN => 4,
        Level::INFO => 6,
        Level::DEBUG | Level::TRACE => 7,
    }
}

/// Returns a formatted event as one journal line: `<priority>`, the event
/// with its final line feed removed and every other line feed and NUL
/// written as `\n` and `\0`, and one line feed.
fn journal_line(priority: u8, event: &[u8]) -> Vec<u8> {
    let event = event.strip_suffix(b"\n").unwrap_or(event);
    let mut line = format!("<{priority}>").into_bytes();
    line.reserve(event.len() + 1);
    for &byte in event {
        match byte {
            b'\n' => line.extend_from_slice(b"\\n"),
            0 => line.extend_from_slice(b"\\0"),
            _ => line.push(byte),
        }
    }
    line.push(b'\n');
    line
}

/// Makes a [`JournalWriter`] for each event.
struct JournalMakeWriter(NonBlocking);

impl<'a> MakeWriter<'a> for JournalMakeWriter {
    type Writer = JournalWriter;

    fn make_writer(&'a self) -> Self::Writer {
        JournalWriter {
            inner: self.0.clone(),
            priority: priority(Level::INFO),
            event: Vec::new(),
        }
    }

    fn make_writer_for(&'a self, meta: &Metadata<'_>) -> Self::Writer {
        JournalWriter {
            inner: self.0.clone(),
            priority: priority(*meta.level()),
            event: Vec::new(),
        }
    }
}

/// Collects one formatted event and writes it as one journal line, in one
/// write, when dropped.
struct JournalWriter {
    inner: NonBlocking,
    priority: u8,
    event: Vec<u8>,
}

impl Write for JournalWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.event.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for JournalWriter {
    fn drop(&mut self) {
        if !self.event.is_empty() {
            let _ = self
                .inner
                .write_all(&journal_line(self.priority, &self.event));
        }
    }
}

/// Replaces the default panic hook by one that logs the panic as one ERROR
/// event and writes nothing else.
fn install_journal_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let thread = std::thread::current();
        tracing::error!(
            "{}",
            panic_message(thread.name(), info.location(), info.payload())
        );
    }));
}

/// Returns the message of a panic:
/// `thread '<name>' panicked at <file>:<line>:<column>: <payload>`.
fn panic_message(
    thread: Option<&str>,
    location: Option<&Location<'_>>,
    payload: &(dyn Any + Send),
) -> String {
    let thread = thread.unwrap_or("<unnamed>");
    let location = location.map_or_else(|| "<unknown>".to_string(), ToString::to_string);
    let payload = if let Some(payload) = payload.downcast_ref::<&str>() {
        payload
    } else if let Some(payload) = payload.downcast_ref::<String>() {
        payload.as_str()
    } else {
        "Box<dyn Any>"
    };
    format!("thread '{thread}' panicked at {location}: {payload}")
}

#[cfg(test)]
mod tests {
    use super::*;

    const STDOUT: FileId = (66306, 1001);
    const STDERR: FileId = (66306, 1002);

    fn journal(value: Option<&str>) -> bool {
        is_journal(value.map(OsStr::new), Some(STDOUT), Some(STDERR))
    }

    #[test]
    fn journal_matches_stdout() {
        assert!(journal(Some("66306:1001")));
    }

    #[test]
    fn journal_matches_stderr_only() {
        assert!(journal(Some("66306:1002")));
        assert!(is_journal(
            Some(OsStr::new("66306:1002")),
            None,
            Some(STDERR)
        ));
    }

    #[test]
    fn journal_mismatch() {
        assert!(!journal(Some("66306:1003")));
        assert!(!journal(Some("1:1001")));
        assert!(!is_journal(Some(OsStr::new("66306:1001")), None, None));
    }

    #[test]
    fn journal_malformed() {
        for value in [
            "12",
            "a:b",
            "1:2:3",
            "",
            ":",
            "66306:",
            ":1001",
            "+66306:1001",
        ] {
            assert!(!journal(Some(value)), "{value:?}");
        }
    }

    #[test]
    fn journal_unset() {
        assert!(!journal(None));
    }

    #[cfg(unix)]
    #[test]
    fn journal_matches_a_descriptor() {
        use std::os::fd::AsFd;
        use std::os::unix::fs::MetadataExt;

        let file = tempfile::tempfile().expect("temporary file");
        let metadata = file.metadata().expect("metadata");
        let id = file_id(file.as_fd());
        assert_eq!(id, Some((metadata.dev(), metadata.ino())));
        let value = format!("{}:{}", metadata.dev(), metadata.ino());
        assert!(is_journal(Some(OsStr::new(&value)), id, None));
        assert!(is_journal(Some(OsStr::new(&value)), None, id));
    }

    #[test]
    fn journal_line_escapes_line_feed_and_nul() {
        assert_eq!(
            journal_line(6, b" INFO a: one\ntwo\0three\n"),
            b"<6> INFO a: one\\ntwo\\0three\n"
        );
    }

    #[test]
    fn journal_line_keeps_backslashes() {
        assert_eq!(journal_line(4, b"a\\nb\\0c\\\n"), b"<4>a\\nb\\0c\\\n");
    }

    #[test]
    fn journal_line_ends_with_one_line_feed() {
        assert_eq!(journal_line(3, b"event"), b"<3>event\n");
        assert_eq!(journal_line(3, b"event\n"), b"<3>event\n");
        assert_eq!(journal_line(3, b"event\n\n"), b"<3>event\\n\n");
    }

    #[test]
    fn priorities() {
        assert_eq!(priority(Level::ERROR), 3);
        assert_eq!(priority(Level::WARN), 4);
        assert_eq!(priority(Level::INFO), 6);
        assert_eq!(priority(Level::DEBUG), 7);
        assert_eq!(priority(Level::TRACE), 7);
    }

    #[test]
    fn panic_message_with_str_payload() {
        let location = Location::caller();
        let payload: Box<dyn Any + Send> = Box::new("boom");
        assert_eq!(
            panic_message(Some("worker"), Some(location), payload.as_ref()),
            format!(
                "thread 'worker' panicked at {}:{}:{}: boom",
                location.file(),
                location.line(),
                location.column()
            )
        );
    }

    #[test]
    fn panic_message_with_string_payload() {
        let payload: Box<dyn Any + Send> = Box::new(String::from("formatted boom"));
        assert_eq!(
            panic_message(Some("main"), None, payload.as_ref()),
            "thread 'main' panicked at <unknown>: formatted boom"
        );
    }

    #[test]
    fn panic_message_with_other_payload() {
        let payload: Box<dyn Any + Send> = Box::new(42_u32);
        assert_eq!(
            panic_message(Some("main"), None, payload.as_ref()),
            "thread 'main' panicked at <unknown>: Box<dyn Any>"
        );
    }

    #[test]
    fn panic_message_of_unnamed_thread() {
        let payload: Box<dyn Any + Send> = Box::new("boom");
        assert_eq!(
            panic_message(None, None, payload.as_ref()),
            "thread '<unnamed>' panicked at <unknown>: boom"
        );
    }
}
