//! Tests of the journal collector's reader against a fake journalctl, and
//! of its stamps and positions.

use std::fmt::Write as _;
use std::fs;
use std::io::{self, Write as _};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use giganto_client::ingest::log::OpLog;
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::time::timeout;

use super::read::{self, Event, Initial, Output, ReaderLink, Start};
use super::*;
use crate::runtime::checkpoints::journal_file;
use crate::sender::CHANNEL_CLOSE_TIMESTAMP;

/// The retry interval the readers are built with.
const RETRY: Duration = Duration::from_millis(200);
/// How long a test waits for something that should happen.
const WAIT: Duration = Duration::from_secs(20);
/// How long a test waits to show that something does not happen.
const SETTLE: Duration = Duration::from_millis(800);

const MACHINE_ID: &str = "0123456789abcdef0123456789abcdef";
const SEQNUM_ID: &str = "fedcba9876543210fedcba9876543210";
const BOOT_ID: &str = "00112233445566778899aabbccddeeff";
const COMMON: &str = "--output=json --all --no-pager \
                      --output-fields=MESSAGE,PRIORITY,_SYSTEMD_UNIT,_PID,UNIT,CONTAINER_NAME";
const KEPT: &str = "clumit-security-a.service";
const DROPPED: &str = "sshd.service";

/// The cursor of the `n`th test entry.
fn cursor(n: u64) -> String {
    format!(
        "s={SEQNUM_ID};i={n:x};b={BOOT_ID};m={n:x};t={:x};x={n:x}",
        time(n)
    )
}

/// The `__REALTIME_TIMESTAMP` of the `n`th test entry.
fn time(n: u64) -> u64 {
    1_700_000_000_000_000 + n
}

/// The `n`th test entry, of `unit`.
fn entry(n: u64, unit: &str) -> Value {
    json!({
        "__CURSOR": cursor(n),
        "__REALTIME_TIMESTAMP": time(n).to_string(),
        "__MONOTONIC_TIMESTAMP": n.to_string(),
        "__SEQNUM": n.to_string(),
        "__SEQNUM_ID": SEQNUM_ID,
        "_BOOT_ID": BOOT_ID,
        "_SYSTEMD_UNIT": unit,
        "PRIORITY": "6",
        "MESSAGE": format!("message {n}"),
    })
}

fn position(n: u64) -> JournalPosition {
    JournalPosition {
        cursor: cursor(n),
        seqnum_id: Some(SEQNUM_ID.to_string()),
        seqnum: Some(n),
        realtime_us: Some(time(n)),
    }
}

/// Tells whether the process runs as a user whom file permissions do not
/// stop.
fn permissions_ignored(dir: &Path) -> bool {
    let probe = dir.join("probe");
    fs::write(&probe, b"x").expect("probe");
    fs::set_permissions(&probe, fs::Permissions::from_mode(0o000)).expect("chmod");
    let ignored = fs::File::open(&probe).is_ok();
    let _ = fs::remove_file(&probe);
    ignored
}

/// A fake journalctl in a directory of its own, a machine-ID file and a
/// journal root with a readable `system.journal`.
struct Fake {
    dir: TempDir,
    state: TempDir,
}

impl Fake {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("a directory");
        let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/journalctl");
        std::os::unix::fs::symlink(script, dir.path().join("journalctl")).expect("symlink");
        fs::write(dir.path().join("entries"), b"").expect("entries");
        fs::write(dir.path().join("machine-id"), format!("{MACHINE_ID}\n")).expect("id");
        let journal = dir.path().join("journal").join(MACHINE_ID);
        fs::create_dir_all(&journal).expect("journal directory");
        fs::write(journal.join("system.journal"), b"").expect("system.journal");
        Self {
            dir,
            state: tempfile::tempdir().expect("a directory"),
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn journal_dir(&self) -> PathBuf {
        self.path("journal").join(MACHINE_ID)
    }

    fn settings(&self) -> Settings {
        Settings {
            paths: Paths {
                journalctl: self.path("journalctl"),
                machine_id: self.path("machine-id"),
                journal_root: self.path("journal"),
            },
            state_dir: self.state.path().to_path_buf(),
            retry_interval: RETRY,
        }
    }

    fn spawn(&self, initial: Initial) -> ReaderLink {
        read::spawn(self.settings(), initial, 0)
    }

    /// Spawns a reader that waits `retry_interval` after a failure.
    fn spawn_retrying(&self, retry_interval: Duration) -> ReaderLink {
        let mut settings = self.settings();
        settings.retry_interval = retry_interval;
        read::spawn(settings, Initial::Wait, 0)
    }

    /// Appends `lines` to the journal.
    fn push(&self, lines: &[Value]) {
        let text = lines.iter().fold(String::new(), |mut text, line| {
            let _ = writeln!(text, "{line}");
            text
        });
        self.push_raw(text.as_bytes());
    }

    fn push_raw(&self, bytes: &[u8]) {
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(self.path("entries"))
            .expect("entries");
        file.write_all(bytes).expect("append");
    }

    /// Sets a fake file, or removes it with `None`.
    fn set(&self, name: &str, content: Option<&str>) {
        match content {
            Some(content) => fs::write(self.path(name), content).expect("write"),
            None => {
                let _ = fs::remove_file(self.path(name));
            }
        }
    }

    /// The arguments of every journalctl run, past the common ones.
    fn args(&self) -> Vec<String> {
        fs::read_to_string(self.path("args"))
            .unwrap_or_default()
            .lines()
            .map(|line| {
                line.strip_prefix(COMMON)
                    .unwrap_or_else(|| panic!("common arguments first: {line}"))
                    .trim()
                    .to_string()
            })
            .collect()
    }

    fn pids(&self) -> Vec<u32> {
        fs::read_to_string(self.path("pids"))
            .unwrap_or_default()
            .lines()
            .map(|line| line.parse().expect("a pid"))
            .collect()
    }

    async fn wait_for_args(&self, count: usize) -> Vec<String> {
        wait_until(&format!("{count} journalctl runs"), || {
            self.args().len() >= count
        })
        .await;
        self.args()
    }
}

async fn wait_until(what: &str, condition: impl Fn() -> bool) {
    let deadline = tokio::time::Instant::now() + WAIT;
    while !condition() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting until {what}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn next(link: &mut ReaderLink) -> Output {
    timeout(WAIT, link.results.recv())
        .await
        .expect("a result in time")
        .expect("the reader runs")
}

/// Asserts that no result arrives for a while.
async fn quiet(link: &mut ReaderLink) {
    if let Ok(output) = timeout(SETTLE, link.results.recv()).await {
        panic!("unexpected result {output:?}");
    }
}

/// The contents of the records of a batch, its position and its `after`.
fn batch(output: Output) -> (Vec<String>, JournalPosition, Option<JournalPosition>) {
    let Event::Batch { records, after } = output.event else {
        panic!("a batch: {output:?}");
    };
    let last = records.last().expect("a record").position.clone();
    let contents = records
        .iter()
        .map(|record| {
            bincode::deserialize::<OpLog>(&record.data)
                .expect("an OpLog")
                .contents
        })
        .collect();
    (contents, last, after)
}

fn messages(range: impl IntoIterator<Item = u64>) -> Vec<String> {
    range.into_iter().map(|n| format!("message {n}")).collect()
}

/// Captures what the current thread logs, at every level.
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
            .with_max_level(tracing::Level::TRACE)
            .with_writer(move || writer.clone())
            .finish();
        (logs, tracing::subscriber::set_default(subscriber))
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().expect("lock")).into_owned()
    }

    fn count(&self, needle: &str) -> usize {
        self.text().matches(needle).count()
    }
}

#[tokio::test]
async fn catch_up_reads_every_entry_and_follow_continues_after_the_last_read() {
    let fake = Fake::new();
    fake.push(&[entry(1, KEPT), entry(2, DROPPED)]);
    let mut link = fake.spawn(Initial::Wait);
    link.resume(1, None);

    let output = next(&mut link).await;
    assert_eq!(output.resume, 1);
    let (contents, last, after) = batch(output);
    assert_eq!(contents, messages([1]));
    assert_eq!(last, position(1));
    assert_eq!(after, Some(position(2)));
    assert_eq!(
        fake.wait_for_args(2).await,
        [
            String::new(),
            format!("--follow --lines=all --after-cursor={}", cursor(2))
        ]
    );

    fake.push(&[entry(3, KEPT), entry(4, KEPT)]);
    let (contents, last, after) = batch(next(&mut link).await);
    assert_eq!(contents, messages([3, 4]));
    assert_eq!(last, position(4));
    assert_eq!(after, None);
    // Entries dropped while no record is pending are reported once.
    fake.push(&[entry(5, DROPPED), entry(6, DROPPED)]);
    let output = next(&mut link).await;
    assert!(
        matches!(&output.event, Event::Position(position) if *position == super::tests::position(6)),
        "{output:?}"
    );
    quiet(&mut link).await;
    assert_eq!(fake.args().len(), 2);
}

#[tokio::test]
async fn resumes_read_after_their_position() {
    let fake = Fake::new();
    fake.push(&[entry(1, KEPT), entry(2, KEPT), entry(3, DROPPED)]);
    let mut link = fake.spawn(Initial::Wait);
    link.resume(4, Some(position(1)));
    let output = next(&mut link).await;
    assert_eq!(output.resume, 4);
    let (contents, last, after) = batch(output);
    assert_eq!(contents, messages([2]));
    assert_eq!(last, position(2));
    assert_eq!(after, Some(position(3)));
    assert_eq!(
        fake.wait_for_args(2).await,
        [
            format!("--after-cursor={}", cursor(1)),
            format!("--follow --lines=all --after-cursor={}", cursor(3)),
        ]
    );
}

#[tokio::test]
async fn follow_starts_after_the_start_cursor_when_catch_up_reads_nothing() {
    let fake = Fake::new();
    fake.push(&[entry(1, KEPT), entry(2, KEPT)]);
    let mut link = fake.spawn(Initial::Wait);
    link.resume(1, Some(position(2)));
    assert_eq!(
        fake.wait_for_args(2).await,
        [
            format!("--after-cursor={}", cursor(2)),
            format!("--follow --lines=all --after-cursor={}", cursor(2)),
        ]
    );
    quiet(&mut link).await;
}

#[tokio::test]
async fn an_empty_journal_is_followed_from_its_start() {
    let fake = Fake::new();
    let mut link = fake.spawn(Initial::Wait);
    link.resume(1, None);
    assert_eq!(
        fake.wait_for_args(2).await,
        [String::new(), "--follow --lines=all".to_string()]
    );
    fake.push(&[entry(1, KEPT)]);
    let (contents, _, _) = batch(next(&mut link).await);
    assert_eq!(contents, messages([1]));
}

#[tokio::test]
async fn nothing_runs_before_the_first_resume() {
    let fake = Fake::new();
    fake.push(&[entry(1, KEPT)]);
    let mut link = fake.spawn(Initial::Load);
    let output = next(&mut link).await;
    assert_eq!(output.resume, 0);
    assert!(
        matches!(output.event, Event::Ready(Start::Missing)),
        "{output:?}"
    );
    quiet(&mut link).await;
    assert_eq!(fake.args(), Vec::<String>::new());
    link.resume(1, None);
    let (contents, _, _) = batch(next(&mut link).await);
    assert_eq!(contents, messages([1]));
}

#[tokio::test]
async fn a_saved_checkpoint_is_the_start() {
    let fake = Fake::new();
    fs::create_dir(fake.state.path().join("checkpoints")).expect("directory");
    fs::write(
        journal_file(fake.state.path()),
        crate::runtime::checkpoints::encode_journal(&position(7)),
    )
    .expect("checkpoint");
    let mut link = fake.spawn(Initial::Load);
    let output = next(&mut link).await;
    assert!(
        matches!(&output.event, Event::Ready(Start::Found(found)) if *found == position(7)),
        "{output:?}"
    );
    assert_eq!(fake.args(), Vec::<String>::new());
}

#[tokio::test]
async fn a_corrupt_checkpoint_reads_the_tail() {
    for (corrupt, reason) in [
        ("garbage", "not valid JSON"),
        ("{\"type\":\"log\"}", "type is not journal"),
    ] {
        let fake = Fake::new();
        fake.push(&[entry(1, KEPT), entry(2, DROPPED)]);
        fs::create_dir(fake.state.path().join("checkpoints")).expect("directory");
        fs::write(journal_file(fake.state.path()), corrupt).expect("checkpoint");
        let mut link = fake.spawn(Initial::Load);
        let output = next(&mut link).await;
        assert_eq!(
            output.event_start(),
            Some(&Start::Corrupt {
                reason: reason.to_string(),
                tail: Some(position(2)),
            })
        );
        assert_eq!(fake.args(), ["--lines=1"]);
    }

    // An empty journal has no tail.
    let fake = Fake::new();
    fs::create_dir(fake.state.path().join("checkpoints")).expect("directory");
    fs::write(journal_file(fake.state.path()), "garbage").expect("checkpoint");
    let mut link = fake.spawn(Initial::Load);
    let output = next(&mut link).await;
    assert_eq!(
        output.event_start(),
        Some(&Start::Corrupt {
            reason: "not valid JSON".to_string(),
            tail: None,
        })
    );
}

#[tokio::test]
async fn a_failing_tail_read_is_retried_before_the_first_result() {
    let (logs, _guard) = Logs::capture();
    let fake = Fake::new();
    fake.push(&[entry(1, KEPT)]);
    fake.set("status", Some("4"));
    fs::create_dir(fake.state.path().join("checkpoints")).expect("directory");
    fs::write(journal_file(fake.state.path()), "garbage").expect("checkpoint");
    let mut link = fake.spawn(Initial::Load);
    fake.wait_for_args(3).await;
    assert!(link.results.is_empty());
    assert_eq!(
        logs.count("journalctl ended with exit status: 4 while reading the newest entry"),
        1,
        "{}",
        logs.text()
    );
    fake.set("status", None);
    let output = next(&mut link).await;
    assert_eq!(
        output.event_start(),
        Some(&Start::Corrupt {
            reason: "not valid JSON".to_string(),
            tail: Some(position(1)),
        })
    );
}

impl Output {
    fn event_start(&self) -> Option<&Start> {
        match &self.event {
            Event::Ready(start) => Some(start),
            _ => None,
        }
    }
}

#[tokio::test]
async fn batches_hold_at_most_1000_records() {
    let fake = Fake::new();
    fake.push(&(1..=2500).map(|n| entry(n, KEPT)).collect::<Vec<_>>());
    let mut link = fake.spawn(Initial::Wait);
    link.resume(1, None);
    let mut sizes = Vec::new();
    let mut all = Vec::new();
    while all.len() < 2500 {
        let (contents, _, _) = batch(next(&mut link).await);
        sizes.push(contents.len());
        all.extend(contents);
    }
    assert_eq!(sizes, [1000, 1000, 500]);
    assert_eq!(all, messages(1..=2500));
}

#[tokio::test]
async fn batches_hold_at_most_4_mib() {
    let fake = Fake::new();
    let big = "x".repeat(60 * 1024);
    fake.push(
        &(1..=150)
            .map(|n| {
                let mut entry = entry(n, KEPT);
                entry["MESSAGE"] = Value::from(format!("{n} {big}"));
                entry
            })
            .collect::<Vec<_>>(),
    );
    let mut link = fake.spawn(Initial::Wait);
    link.resume(1, None);
    let mut count = 0;
    let mut batches = Vec::new();
    while count < 150 {
        let output = next(&mut link).await;
        let Event::Batch { records, .. } = output.event else {
            panic!("a batch");
        };
        count += records.len();
        batches.push(
            records
                .iter()
                .map(|record| record.data.len())
                .collect::<Vec<_>>(),
        );
    }
    assert!(batches.len() >= 3, "{}", batches.len());
    for sizes in &batches[..batches.len() - 1] {
        let total = sizes.iter().sum::<usize>();
        assert!(total <= 4 * 1024 * 1024, "{total}");
        // The next record would not have fit.
        assert!(total + sizes[0] > 4 * 1024 * 1024, "{total}");
    }
}

#[tokio::test]
async fn an_over_long_line_is_skipped_with_a_warning() {
    let (logs, _guard) = Logs::capture();
    let fake = Fake::new();
    // A line of exactly 1 MiB is read.
    let mut exact = entry(1, KEPT);
    exact["MESSAGE"] = Value::from(String::new());
    let len = exact.to_string().len();
    exact["MESSAGE"] = Value::from("y".repeat(1024 * 1024 - len));
    assert_eq!(exact.to_string().len(), 1024 * 1024);
    // A line of 1 MiB + 1 is skipped.
    let mut over = entry(2, KEPT);
    over["MESSAGE"] = Value::from(String::new());
    let len = over.to_string().len();
    over["MESSAGE"] = Value::from("z".repeat(1024 * 1024 + 1 - len));
    fake.push(&[exact, over, entry(3, KEPT)]);

    let mut link = fake.spawn(Initial::Wait);
    link.resume(1, None);
    let output = next(&mut link).await;
    let Event::Batch { records, .. } = output.event else {
        panic!("a batch");
    };
    assert_eq!(records.len(), 2);
    let first = bincode::deserialize::<OpLog>(&records[0].data).expect("an OpLog");
    assert!(first.contents.starts_with("yyy"));
    assert!(first.contents.ends_with("[truncated]"));
    assert_eq!(records[0].position, position(1));
    assert_eq!(records[1].position, position(3));
    let text = logs.text();
    assert_eq!(
        text.matches("skipped 1 journal entries whose journalctl output line is longer than 1 MiB")
            .count(),
        1,
        "{text}"
    );
    assert!(text.contains("WARN"), "{text}");
    // The follow run starts after the last entry read.
    assert_eq!(
        fake.wait_for_args(2).await[1],
        format!("--follow --lines=all --after-cursor={}", cursor(3))
    );
}

/// Kills the process `pid`.
fn kill(pid: u32) {
    let status = std::process::Command::new("kill")
        .args(["-KILL", &pid.to_string()])
        .status()
        .expect("kill runs");
    assert!(status.success());
}

#[tokio::test]
async fn a_follow_exit_restarts_catch_up_after_the_last_entry_read() {
    let (logs, _guard) = Logs::capture();
    let fake = Fake::new();
    fake.push(&[entry(1, KEPT)]);
    let mut link = fake.spawn_retrying(Duration::from_secs(1));
    link.resume(1, None);
    let (contents, _, _) = batch(next(&mut link).await);
    assert_eq!(contents, messages([1]));
    fake.wait_for_args(2).await;
    fake.push(&[entry(2, KEPT), entry(3, DROPPED)]);
    let (contents, _, after) = batch(next(&mut link).await);
    assert_eq!(contents, messages([2]));
    assert_eq!(after, Some(position(3)));

    // journalctl ends while following.
    kill(*fake.pids().last().expect("a pid"));
    wait_until("the exit is logged", || {
        logs.count("journalctl ended with signal: 9 (SIGKILL) while following the journal") == 1
    })
    .await;
    assert_eq!(fake.args().len(), 2, "journalctl waits to be started again");
    fake.push(&[entry(4, KEPT)]);
    let (contents, _, _) = batch(next(&mut link).await);
    assert_eq!(contents, messages([4]));
    assert_eq!(
        fake.wait_for_args(4).await,
        [
            String::new(),
            format!("--follow --lines=all --after-cursor={}", cursor(1)),
            format!("--after-cursor={}", cursor(3)),
            format!("--follow --lines=all --after-cursor={}", cursor(4)),
        ]
    );
    // Nothing is read twice.
    quiet(&mut link).await;
}

#[tokio::test]
async fn a_failed_catch_up_keeps_its_batch_and_restarts_after_the_last_entry_read() {
    let (logs, _guard) = Logs::capture();
    let fake = Fake::new();
    fake.push(&[entry(1, KEPT), entry(2, DROPPED)]);
    fake.set("status", Some("1"));
    let mut link = fake.spawn_retrying(Duration::from_secs(1));
    link.resume(1, None);
    // The batch read before the exit is returned once.
    let (contents, last, after) = batch(next(&mut link).await);
    assert_eq!(contents, messages([1]));
    assert_eq!(last, position(1));
    assert_eq!(after, Some(position(2)));
    fake.set("status", None);
    let args = fake.wait_for_args(3).await;
    assert_eq!(
        args[..3],
        [
            String::new(),
            format!("--after-cursor={}", cursor(2)),
            format!("--follow --lines=all --after-cursor={}", cursor(2)),
        ]
    );
    assert_eq!(
        logs.count("journalctl ended with exit status: 1 while catching up"),
        1,
        "{}",
        logs.text()
    );
    quiet(&mut link).await;
}

#[tokio::test]
async fn an_unparsable_line_restarts_catch_up_without_logging_it() {
    let (logs, _guard) = Logs::capture();
    let fake = Fake::new();
    fake.push(&[entry(1, KEPT)]);
    fake.push_raw(b"secret garbage\n");
    fake.push(&[entry(3, KEPT)]);
    let mut link = fake.spawn_retrying(Duration::from_secs(1));
    link.resume(1, None);
    let (contents, _, _) = batch(next(&mut link).await);
    assert_eq!(contents, messages([1]));
    wait_until("the failure is logged", || {
        logs.count("unparsable line of 14 bytes") > 0
    })
    .await;
    // The line is replaced before journalctl is started again.
    let text = fs::read_to_string(fake.path("entries")).expect("entries");
    fake.set(
        "entries",
        Some(&text.replace("secret garbage", &entry(2, KEPT).to_string())),
    );
    let (contents, _, _) = batch(next(&mut link).await);
    assert_eq!(contents, messages([2, 3]));
    let args = fake.args();
    assert_eq!(args[1], format!("--after-cursor={}", cursor(1)), "{args:?}");
    assert!(!logs.text().contains("secret"), "{}", logs.text());
}

#[tokio::test]
async fn a_missing_journalctl_is_retried_with_rate_limited_warnings() {
    let (logs, _guard) = Logs::capture();
    let fake = Fake::new();
    fs::remove_file(fake.path("journalctl")).expect("remove");
    let mut link = fake.spawn(Initial::Wait);
    link.resume(1, None);
    wait_until("the failure is logged", || logs.count("cannot start") > 0).await;
    tokio::time::sleep(4 * RETRY).await;
    assert_eq!(logs.count("cannot start"), 1, "{}", logs.text());

    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/journalctl");
    std::os::unix::fs::symlink(script, fake.path("journalctl")).expect("symlink");
    fake.push(&[entry(1, KEPT)]);
    let (contents, _, _) = batch(next(&mut link).await);
    assert_eq!(contents, messages([1]));
}

#[tokio::test]
async fn standard_error_is_logged_at_most_once_per_second() {
    let (logs, _guard) = Logs::capture();
    let fake = Fake::new();
    fake.set(
        "stderr",
        Some("first problem\nsecond problem\nthird problem\n"),
    );
    let link = fake.spawn(Initial::Wait);
    link.resume(1, None);
    fake.wait_for_args(2).await;
    tokio::time::sleep(SETTLE).await;
    let text = logs.text();
    let lines = text
        .lines()
        .filter(|line| line.contains("journalctl: "))
        .collect::<Vec<_>>();
    assert_eq!(lines.len(), 1, "{text}");
    assert!(
        lines[0].contains("WARN") && lines[0].contains("first problem"),
        "{text}"
    );
    drop(link);
}

#[tokio::test]
async fn a_pause_kills_and_reaps_journalctl_until_the_next_resume() {
    let fake = Fake::new();
    fake.push(&[entry(1, KEPT)]);
    let mut link = fake.spawn(Initial::Wait);
    link.resume(1, None);
    batch(next(&mut link).await);
    fake.wait_for_args(2).await;
    let follow = *fake.pids().last().expect("a pid");
    assert!(Path::new(&format!("/proc/{follow}")).exists());

    link.pause().await;
    assert!(
        !Path::new(&format!("/proc/{follow}")).exists(),
        "journalctl is killed and reaped"
    );
    fake.push(&[entry(2, KEPT)]);
    quiet(&mut link).await;
    assert_eq!(fake.args().len(), 2, "nothing runs while paused");

    // A resume from an earlier position reads its entries again.
    link.resume(2, None);
    let output = next(&mut link).await;
    assert_eq!(output.resume, 2);
    let (contents, _, _) = batch(output);
    assert_eq!(contents, messages([1, 2]));
}

#[tokio::test]
async fn dropping_the_link_stops_journalctl() {
    let fake = Fake::new();
    let link = fake.spawn(Initial::Wait);
    link.resume(1, None);
    fake.wait_for_args(2).await;
    let follow = *fake.pids().last().expect("a pid");
    drop(link);
    wait_until("journalctl ends", || {
        !Path::new(&format!("/proc/{follow}")).exists()
    })
    .await;
}

#[tokio::test]
async fn a_full_channel_stops_reading() {
    let fake = Fake::new();
    fake.push(&(1..=5000).map(|n| entry(n, KEPT)).collect::<Vec<_>>());
    let mut link = fake.spawn(Initial::Wait);
    link.resume(1, None);
    // Two results fill the channel; the reader holds a third.
    wait_until("the channel is full", || link.results.len() == 2).await;
    tokio::time::sleep(SETTLE).await;
    assert_eq!(link.results.len(), 2);
    let mut all = Vec::new();
    while all.len() < 5000 {
        all.extend(batch(next(&mut link).await).0);
    }
    assert_eq!(all, messages(1..=5000));
}

/// Waits for the reader's first result, which follows the access check.
async fn ready(link: &mut ReaderLink) {
    let output = next(link).await;
    assert!(matches!(output.event, Event::Ready(_)), "{output:?}");
}

#[tokio::test]
async fn the_access_check_holds_back_journalctl_until_it_passes() {
    let (logs, _guard) = Logs::capture();
    let fake = Fake::new();
    fake.set("machine-id", Some("not-a-machine-id\n"));
    let mut link = fake.spawn(Initial::Load);
    wait_until("the error is logged", || {
        logs.count("cannot read the system journal; is the unit in group adm?") > 0
    })
    .await;
    tokio::time::sleep(3 * RETRY).await;
    let text = logs.text();
    assert_eq!(
        text.matches("cannot read the system journal; is the unit in group adm?")
            .count(),
        1,
        "{text}"
    );
    assert!(
        text.contains("ERROR") && text.contains("valid machine ID"),
        "{text}"
    );
    assert!(link.results.is_empty());
    assert_eq!(fake.args(), Vec::<String>::new());

    fake.set("machine-id", Some(MACHINE_ID));
    ready(&mut link).await;
    assert_eq!(logs.count("the system journal is readable"), 1);
    assert_eq!(fake.args(), Vec::<String>::new());
}

#[tokio::test]
async fn the_access_check_needs_a_system_journal_file() {
    let (logs, _guard) = Logs::capture();
    let fake = Fake::new();
    let dir = fake.journal_dir();
    fs::remove_file(dir.join("system.journal")).expect("remove");
    fs::write(dir.join("user-1000.journal"), b"").expect("a user journal");
    fs::write(dir.join("system@x.journal~"), b"").expect("a corrupt archive");
    let mut link = fake.spawn(Initial::Load);
    wait_until("the error is logged", || {
        logs.count("holds no system journal file") > 0
    })
    .await;
    assert!(link.results.is_empty());

    // A readable archive alone passes.
    fs::write(dir.join("system@0123-0456.journal"), b"").expect("an archive");
    ready(&mut link).await;
    assert_eq!(fake.args(), Vec::<String>::new());
}

#[tokio::test]
async fn the_access_check_lists_the_directory_and_opens_the_file() {
    let fake = Fake::new();
    if permissions_ignored(fake.dir.path()) {
        eprintln!("skipped: file permissions do not apply to this user");
        return;
    }
    let (logs, _guard) = Logs::capture();
    let dir = fake.journal_dir();

    // An unlistable directory.
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o000)).expect("chmod");
    let link = fake.spawn(Initial::Load);
    wait_until("the error is logged", || logs.count("cannot list") > 0).await;
    assert!(link.results.is_empty());
    drop(link);

    // A listable directory whose system.journal cannot be opened, though an
    // archive could.
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).expect("chmod");
    fs::write(dir.join("system@0123-0456.journal"), b"").expect("an archive");
    let journal = dir.join("system.journal");
    fs::set_permissions(&journal, fs::Permissions::from_mode(0o000)).expect("chmod");
    let mut link = fake.spawn(Initial::Load);
    wait_until("the error is logged", || logs.count("cannot open") > 0).await;
    tokio::time::sleep(SETTLE).await;
    assert!(link.results.is_empty());
    assert_eq!(fake.args(), Vec::<String>::new());

    fs::set_permissions(&journal, fs::Permissions::from_mode(0o640)).expect("chmod");
    ready(&mut link).await;
}

#[test]
fn stamps_follow_entry_times_and_strictly_increase() {
    let mut stamps = Stamps::default();
    let now = || panic!("an entry with a time is stamped from it");
    // The first entry on a fresh stream.
    assert_eq!(stamps.next(Some(10), now), 10_000);
    // Increasing times.
    assert_eq!(stamps.next(Some(12), now), 12_000);
    // Equal times are spread by nanoseconds, however many there are.
    let mut previous = stamps.next(Some(20), now);
    assert_eq!(previous, 20_000);
    for _ in 0..1500 {
        let stamp = stamps.next(Some(20), now);
        assert_eq!(stamp, previous + 1);
        previous = stamp;
    }
    assert_eq!(previous, 21_500);
    // The next microsecond, already passed by the spreading.
    assert_eq!(stamps.next(Some(21), now), 21_501);
    assert_eq!(stamps.next(Some(30), now), 30_000);
    // A clock step back is stamped after the previous stamp until the
    // clock passes it again.
    assert_eq!(stamps.next(Some(5), now), 30_001);
    assert_eq!(stamps.next(Some(6), now), 30_002);
    assert_eq!(stamps.next(Some(31), now), 31_000);
    // A missing or unusable time.
    assert_eq!(stamps.next(None, now), 31_001);
    assert_eq!(stamps.next(Some(u64::MAX), now), 31_002);
    assert_eq!(stamps.next(Some(u64::MAX / 1000), now), 31_003);

    // The first entry of a fresh stream without a time gets the clock.
    let mut stamps = Stamps::default();
    assert_eq!(stamps.next(None, || 77), 77);
    assert_eq!(stamps.next(Some(0), || 0), 78);
    assert_eq!(stamps.next(Some(1), || 0), 1000);
}

/// Positions as the controller applies them: a batch of records ending at
/// entry 3, entries dropped between and after, and its acknowledgement.
#[test]
fn the_acknowledged_position_passes_dropped_entries_once_everything_is_acknowledged() {
    let acks = Acks::new();
    let receiver = acks.replace(true);
    let ack = |timestamp| acks.apply(timestamp, acks.generation(), receiver);
    let mut stamps = Stamps::default();
    acks.opened(position(0));

    // Records 1 and 3 with dropped entry 2 between them, and dropped
    // entries 4 and 5 after them.
    acks.returned(position(3));
    let first = stamps.next(Some(time(1)), now_nanos);
    let last = stamps.next(Some(time(3)), now_nanos);
    acks.queue(last).expect("queued");
    acks.sent();
    acks.consumed(position(5));
    assert_eq!(acks.current(), Some(position(5)));
    assert_eq!(acks.acknowledged(), Some(position(0)));
    // An ACK of the first record matches no batch and acknowledges nothing.
    assert!(!ack(first));
    assert_eq!(acks.acknowledged(), Some(position(0)));

    assert!(ack(last));
    assert_eq!(acks.acknowledged(), Some(position(5)));
    // Giganto repeats its last ACK: nothing new is acknowledged.
    assert!(!ack(last));
    assert_eq!(acks.acknowledged(), Some(position(5)));
    // Later dropped entries move it while nothing is pending.
    acks.consumed(position(6));
    assert_eq!(acks.acknowledged(), Some(position(6)));
    // The close ACK with nothing pending changes nothing.
    assert!(!ack(CHANNEL_CLOSE_TIMESTAMP));
}

/// A stream drop while kept entries wait in an unwritten batch, with every
/// written batch acknowledged: the acknowledged position stays at the last
/// acknowledged batch, from which the reader resumes.
#[test]
fn a_dropped_stream_keeps_the_last_acknowledged_batch() {
    let acks = Acks::new();
    let receiver = acks.replace(true);
    let mut stamps = Stamps::default();
    acks.opened(position(0));
    acks.returned(position(2));
    let stamp = stamps.next(Some(time(2)), now_nanos);
    acks.queue(stamp).expect("queued");
    acks.sent();
    assert!(acks.apply(stamp, acks.generation(), receiver));
    assert_eq!(acks.acknowledged(), Some(position(2)));

    // The next batch, ending at entry 4, fails to be written.
    acks.returned(position(4));
    let entry = acks
        .queue(stamps.next(Some(time(4)), now_nanos))
        .expect("queued");
    acks.failed(entry);
    // The recovery forgets the held batch and replaces the stream.
    acks.dropped();
    acks.replace(true);
    assert_eq!(acks.acknowledged(), Some(position(2)));
    // The resume starts from the acknowledged position.
    acks.opened(position(2));
    assert_eq!(acks.acknowledged(), Some(position(2)));
    assert_eq!(acks.current(), Some(position(2)));
}
