//! Tests of the remote-mode collector runtime against an in-process
//! Giganto-like QUIC server ([`support::giganto`]).

mod support;

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use reproduce::config::remote::{CollectorConfig, LogCollectorConfig, RemoteConfig, StartPosition};
use reproduce::manager::{ConfigRuntime, TlsFiles};
use reproduce::reload::ReloadSignal;
use reproduce::runtime::CollectorRuntime;
use support::giganto::{GIGANTO_VERSION_REQ, Giganto, StreamRecord, Withhold, log_header};
use support::{Files, Logs, Pki, SERVER_NAME};
use tempfile::TempDir;
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

/// The log files of a test.
struct LogFiles {
    dir: TempDir,
}

impl LogFiles {
    fn new() -> Result<Self> {
        let dir = tempfile::tempdir()?;
        std::fs::create_dir(dir.path().join("state"))?;
        Ok(Self { dir })
    }

    /// The state directory of the test's runtime.
    fn state(&self) -> PathBuf {
        self.path("state")
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
    config_start(addr, collectors, StartPosition::Beginning)
}

fn config_start(
    addr: SocketAddr,
    collectors: &[(&str, &Path)],
    start: StartPosition,
) -> RemoteConfig {
    RemoteConfig {
        giganto_ingest_srv_addr: addr,
        giganto_name: SERVER_NAME.to_string(),
        collectors: collectors
            .iter()
            .map(|(kind, path)| {
                CollectorConfig::Log(LogCollectorConfig {
                    kind: (*kind).to_string(),
                    path: path.to_path_buf(),
                    start,
                })
            })
            .collect(),
    }
}

fn runtime(files: &TlsFiles, reload: &ReloadSignal, state_dir: &Path) -> CollectorRuntime {
    CollectorRuntime::new(files.clone(), reload.clone(), state_dir.to_path_buf())
        .with_retry_interval(RETRY)
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

/// The checkpoint file of `kind` in `state_dir`.
fn checkpoint_file(state_dir: &Path, kind: &str) -> PathBuf {
    state_dir
        .join("checkpoints")
        .join("log")
        .join(format!("{kind}.json"))
}

/// The checkpoint of `kind`, if it can be read.
fn checkpoint(state_dir: &Path, kind: &str) -> Option<serde_json::Value> {
    let bytes = std::fs::read(checkpoint_file(state_dir, kind)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// The checkpoint of `kind` for `path` at `offset` in its current file.
#[cfg(unix)]
fn record(kind: &str, path: &Path, offset: u64) -> serde_json::Value {
    use std::os::unix::fs::MetadataExt;

    let metadata = std::fs::metadata(path).expect("the file exists");
    serde_json::json!({
        "type": "log",
        "kind": kind,
        "path": path.to_str().expect("a UTF-8 path"),
        "dev": metadata.dev(),
        "ino": metadata.ino(),
        "offset": offset,
    })
}

fn length(path: &Path) -> u64 {
    std::fs::metadata(path).expect("the file exists").len()
}

/// Waits until the checkpoint of `kind` is `expected`, at most `within`.
async fn wait_for_checkpoint(
    state_dir: &Path,
    kind: &str,
    expected: &serde_json::Value,
    within: Duration,
) {
    let deadline = Instant::now() + within;
    loop {
        let found = checkpoint(state_dir, kind);
        if found.as_ref() == Some(expected) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for the checkpoint of {kind} to be {expected}, found {found:?}"
        );
        sleep(Duration::from_millis(20)).await;
    }
}

/// The stop lines logged for `kind`.
fn stop_lines(text: &str, kind: &str) -> Vec<String> {
    let prefix = format!("Stopped collector {kind} for ");
    text.lines()
        .filter(|line| line.contains(&prefix))
        .map(str::to_string)
        .collect()
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
    let mut runtime = runtime(&files.files, &reload, &logs.state());

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
    let mut runtime = runtime(&files.files, &reload, &logs.state());

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
    let mut runtime = runtime(&files.files, &reload, &logs.state());

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
    let mut runtime = runtime(&files.files, &reload, &logs.state());

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
    let mut runtime = runtime(&files.files, &reload, &logs.state());

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
    sleep(SETTLE).await;
    let lines = stop_lines(&logs_capture.text(), "kind_b");
    assert_eq!(lines.len(), 1, "{lines:?}");
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
    let mut runtime = runtime(&files.files, &reload, &logs.state());

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
    let mut runtime = runtime(&files.files, &reload, &logs.state());

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
    let mut runtime = runtime(&files.files, &reload, &logs.state());

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
    let mut runtime = runtime(&files.files, &reload, &logs.state());

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
    let mut runtime = CollectorRuntime::new(files.files.clone(), reload.clone(), logs.state())
        .with_retry_interval(retry);

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
    let mut runtime = runtime(&files.files, &reload, &logs.state());

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
    let (logs_capture, _guard) = Logs::capture();
    let (_pki, giganto, files) = setup()?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1"])?;
    let b = logs.create("b.log", &["b1"])?;
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload, &logs.state());

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
    sleep(SETTLE).await;
    assert_one_deadline_stop_line(&logs_capture.text(), "kind_b", &b);

    giganto.withhold(Withhold::Nothing);
    runtime.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn shutdown_without_close_acks_returns_after_the_deadline() -> Result<()> {
    let (logs_capture, _guard) = Logs::capture();
    let (_pki, giganto, files) = setup()?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1"])?;
    let b = logs.create("b.log", &["b1"])?;
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload, &logs.state());

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
    sleep(SETTLE).await;
    let text = logs_capture.text();
    assert_one_deadline_stop_line(&text, "kind_a", &a);
    assert_one_deadline_stop_line(&text, "kind_b", &b);
    Ok(())
}

/// Asserts that the collector of `kind` logged one stop line, for a close
/// cut off at the deadline.
///
/// The close's own 15 s wait for the close ACK ends within the same timer
/// tick as the deadline, so either side can log the line, never both.
fn assert_one_deadline_stop_line(text: &str, kind: &str, path: &Path) {
    let lines = stop_lines(text, kind);
    assert_eq!(lines.len(), 1, "{text}");
    let prefix = format!("Stopped collector {kind} for {} ", path.display());
    assert!(
        lines[0].contains(&format!(
            "{prefix}at the close deadline, without waiting further"
        )) || lines[0].contains(&format!("{prefix}with close ACK TimedOut")),
        "{}",
        lines[0]
    );
}

#[tokio::test]
async fn shutdown_after_a_dropped_apply_stops_every_collector() -> Result<()> {
    let (logs_capture, _guard) = Logs::capture();
    let (_pki, giganto, files) = setup()?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1"])?;
    let b = logs.create("b.log", &["b1"])?;
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload, &logs.state());

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

#[cfg(unix)]
#[tokio::test]
async fn checkpoints_follow_the_acknowledged_lines() -> Result<()> {
    let (_pki, giganto, files) = setup()?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1"])?;
    let b = logs.create("b.log", &["b1", "", "b2"])?;
    let state = logs.state();
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload, &state);

    runtime
        .apply(config(giganto.addr, &[("kind_a", &a), ("kind_b", &b)]))
        .await;
    wait_for_lines(&giganto, "kind_a", &["a1"]).await;
    wait_for_lines(&giganto, "kind_b", &["b1", "b2"]).await;
    wait_for_checkpoint(&state, "kind_a", &record("kind_a", &a, length(&a)), WAIT).await;
    wait_for_checkpoint(&state, "kind_b", &record("kind_b", &b, length(&b)), WAIT).await;

    // While the readers wait at EOF, each acknowledged line reaches the
    // checkpoint within a second.
    append(&a, "a2")?;
    append(&b, "b3")?;
    wait_for_lines(&giganto, "kind_a", &["a2"]).await;
    wait_for_lines(&giganto, "kind_b", &["b3"]).await;
    let within = Duration::from_secs(1) + Duration::from_millis(500);
    wait_for_checkpoint(&state, "kind_a", &record("kind_a", &a, length(&a)), within).await;
    wait_for_checkpoint(&state, "kind_b", &record("kind_b", &b, length(&b)), within).await;

    // A clean stop saves everything written.
    append(&a, "a3")?;
    wait_for_lines(&giganto, "kind_a", &["a3"]).await;
    runtime.shutdown().await;
    assert_eq!(
        checkpoint(&state, "kind_a"),
        Some(record("kind_a", &a, length(&a)))
    );
    assert_eq!(
        checkpoint(&state, "kind_b"),
        Some(record("kind_b", &b, length(&b)))
    );
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn shutdown_without_acks_saves_the_last_acknowledged_line() -> Result<()> {
    let (_pki, giganto, files) = setup()?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1"])?;
    let b = logs.create("b.log", &["b1"])?;
    let state = logs.state();
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload, &state);

    runtime
        .apply(config(giganto.addr, &[("kind_a", &a), ("kind_b", &b)]))
        .await;
    wait_for_lines(&giganto, "kind_a", &["a1"]).await;
    let acknowledged = length(&a);
    wait_for_checkpoint(&state, "kind_a", &record("kind_a", &a, acknowledged), WAIT).await;

    // kind_a's later lines and its close are never acknowledged.
    giganto.withhold_acks(&["kind_a"]);
    giganto.withhold(Withhold::Kinds(HashSet::from(["kind_a".to_string()])));
    append(&a, "a2")?;
    append(&a, "a3")?;
    wait_for_lines(&giganto, "kind_a", &["a2", "a3"]).await;
    sleep(SETTLE).await;
    assert_eq!(
        checkpoint(&state, "kind_a"),
        Some(record("kind_a", &a, acknowledged))
    );

    let started = Instant::now();
    runtime.shutdown().await;
    assert!(started.elapsed() >= CLOSE_DEADLINE);
    assert_eq!(
        checkpoint(&state, "kind_a"),
        Some(record("kind_a", &a, acknowledged))
    );
    assert_eq!(
        checkpoint(&state, "kind_b"),
        Some(record("kind_b", &b, length(&b)))
    );
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn a_replaced_stream_keeps_the_acknowledged_position() -> Result<()> {
    let (_pki, giganto, files) = setup()?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1"])?;
    let state = logs.state();
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload, &state);

    runtime.apply(config(giganto.addr, &[("kind_a", &a)])).await;
    wait_for_lines(&giganto, "kind_a", &["a1"]).await;
    let acknowledged = length(&a);
    wait_for_checkpoint(&state, "kind_a", &record("kind_a", &a, acknowledged), WAIT).await;

    // a2 is never acknowledged, and its stream is stopped.
    giganto.withhold_acks(&["kind_a"]);
    append(&a, "a2")?;
    wait_for_lines(&giganto, "kind_a", &["a2"]).await;
    giganto.stop_stream_of("kind_a")?;
    append(&a, "a3")?;
    wait_for("a3 arrives on a new stream", WAIT, || {
        giganto
            .streams_of("kind_a")
            .get(1)
            .is_some_and(|stream| stream.lines().contains(&"a3".to_string()))
    })
    .await;
    // The unacknowledged a2 is sent again on the new stream, from the
    // acknowledged position.
    assert_eq!(giganto.streams_of("kind_a")[1].lines(), ["a2", "a3"]);

    // The position stays put while the reader idles.
    sleep(SETTLE).await;
    assert_eq!(
        checkpoint(&state, "kind_a"),
        Some(record("kind_a", &a, acknowledged))
    );

    // It moves on once a line sent on the new stream is acknowledged.
    giganto.withhold_acks(&[]);
    append(&a, "a4")?;
    wait_for_lines(&giganto, "kind_a", &["a4"]).await;
    wait_for_checkpoint(&state, "kind_a", &record("kind_a", &a, length(&a)), WAIT).await;

    runtime.shutdown().await;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn the_starting_position_is_saved_before_sending() -> Result<()> {
    let (logs_capture, _guard) = Logs::capture();
    let (_pki, giganto, files) = setup()?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1"])?;
    let state = logs.state();
    // A directory in the way of the temporary file makes every save fail.
    let obstacle = state
        .join("checkpoints")
        .join("log")
        .join("kind_a.json.tmp");
    std::fs::create_dir_all(&obstacle)?;
    giganto.withhold_acks(&["kind_a"]);
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload, &state);

    runtime.apply(config(giganto.addr, &[("kind_a", &a)])).await;
    // More than two retries of every 3 s.
    sleep(Duration::from_secs(7)).await;
    assert!(giganto.streams().is_empty(), "{:?}", giganto.streams());
    assert!(checkpoint(&state, "kind_a").is_none());
    let text = logs_capture.text();
    let warnings = text
        .lines()
        .filter(|line| {
            line.contains("WARN") && line.contains("Cannot save the checkpoint of kind_a")
        })
        .count();
    assert_eq!(warnings, 1, "{text}");

    std::fs::remove_dir(&obstacle)?;
    wait_for_lines(&giganto, "kind_a", &["a1"]).await;
    // Nothing is acknowledged, so the checkpoint is the starting position.
    assert_eq!(checkpoint(&state, "kind_a"), Some(record("kind_a", &a, 0)));
    assert!(
        logs_capture
            .text()
            .contains("Saved the checkpoint of kind_a again")
    );

    giganto.withhold_acks(&[]);
    runtime.shutdown().await;
    assert!(!logs_capture.text().contains("ERROR"));
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn a_corrupt_checkpoint_is_replaced_by_the_starting_position() -> Result<()> {
    let (logs_capture, _guard) = Logs::capture();
    let (_pki, giganto, files) = setup()?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1"])?;
    let state = logs.state();
    let file = checkpoint_file(&state, "kind_a");
    std::fs::create_dir_all(file.parent().context("a parent")?)?;
    std::fs::write(&file, b"{\"type\":\"log\",")?;
    giganto.withhold_acks(&["kind_a"]);
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload, &state);

    runtime.apply(config(giganto.addr, &[("kind_a", &a)])).await;
    // The starting position is the end of the file.
    wait_for_checkpoint(&state, "kind_a", &record("kind_a", &a, length(&a)), WAIT).await;
    append(&a, "a2")?;
    wait_for_lines(&giganto, "kind_a", &["a2"]).await;
    assert_eq!(giganto.lines("kind_a"), ["a2"], "a1 is not sent");
    let text = logs_capture.text();
    let expected = format!(
        "Checkpoint {} is unusable: not valid JSON; using the end of {} instead",
        file.display(),
        a.display()
    );
    assert!(
        text.lines()
            .any(|line| line.contains("WARN") && line.contains(&expected)),
        "{text}"
    );

    giganto.withhold_acks(&[]);
    runtime.shutdown().await;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn applies_delete_and_replace_checkpoints() -> Result<()> {
    let (logs_capture, _guard) = Logs::capture();
    let (_pki, giganto, files) = setup()?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1"])?;
    let moved = logs.create("moved.log", &["m1", "m2"])?;
    let b = logs.create("b.log", &["b1"])?;
    let state = logs.state();
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload, &state);

    runtime
        .apply(config(giganto.addr, &[("kind_a", &a), ("kind_b", &b)]))
        .await;
    wait_for_lines(&giganto, "kind_a", &["a1"]).await;
    wait_for_lines(&giganto, "kind_b", &["b1"]).await;
    wait_for_checkpoint(&state, "kind_a", &record("kind_a", &a, length(&a)), WAIT).await;
    wait_for_checkpoint(&state, "kind_b", &record("kind_b", &b, length(&b)), WAIT).await;
    let journal = state.join("checkpoints").join("journal.json");
    std::fs::write(&journal, b"{}\n")?;
    let stray = state
        .join("checkpoints")
        .join("log")
        .join("kind_b.json.tmp");
    std::fs::write(&stray, b"{")?;
    // kind_b has a line in flight as it is removed.
    append(&b, "b2")?;

    runtime
        .apply(config(giganto.addr, &[("kind_a", &moved)]))
        .await;
    assert!(!checkpoint_file(&state, "kind_b").exists());
    assert!(!stray.exists());
    assert!(journal.exists());
    assert!(
        logs_capture
            .text()
            .contains("Deleted the checkpoint of kind_b")
    );
    wait_for_checkpoint(
        &state,
        "kind_a",
        &record("kind_a", &moved, length(&moved)),
        WAIT,
    )
    .await;
    assert!(logs_capture.text().contains(&format!(
        "Checkpoint {} is for {}, not {}; it will be replaced",
        checkpoint_file(&state, "kind_a").display(),
        a.display(),
        moved.display()
    )));

    // Nothing of a removed collector lands afterwards.
    sleep(SETTLE).await;
    assert!(!checkpoint_file(&state, "kind_b").exists());
    assert_eq!(
        checkpoint(&state, "kind_a"),
        Some(record("kind_a", &moved, length(&moved)))
    );

    runtime.shutdown().await;
    assert!(!checkpoint_file(&state, "kind_b").exists());
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
start = "beginning"

[[collectors]]
type = "log"
kind = "kind_b"
path = "{}"
start = "beginning"
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
    for (kind, path) in [("kind_a", &a), ("kind_b", &b)] {
        assert_eq!(
            checkpoint(state_dir.path(), kind),
            Some(record(kind, path, length(path))),
            "{}",
            output()
        );
    }
    Ok(())
}

/// Copies `path` aside and truncates it, as a copy-truncate rotation does,
/// then writes `lines` to it.
fn copy_truncate(path: &Path, lines: &[&str]) -> Result<()> {
    let mut copy = path.as_os_str().to_owned();
    copy.push(".1");
    std::fs::copy(path, &copy)?;
    std::fs::OpenOptions::new()
        .write(true)
        .open(path)?
        .set_len(0)?;
    for line in lines {
        append(path, line)?;
    }
    Ok(())
}

/// Tells whether this process has `path` open.
#[cfg(unix)]
fn is_open(path: &Path) -> bool {
    let path = std::fs::canonicalize(path).expect("the file exists");
    open_paths().contains(&path)
}

/// The files this process has open.
#[cfg(target_os = "linux")]
fn open_paths() -> Vec<PathBuf> {
    std::fs::read_dir("/proc/self/fd")
        .expect("/proc/self/fd")
        .flatten()
        .filter_map(|entry| std::fs::read_link(entry.path()).ok())
        .collect()
}

/// The files this process has open.
#[cfg(all(unix, not(target_os = "linux")))]
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

/// The lines `kind` received on its streams from the `from`th on.
fn lines_from(giganto: &Giganto, kind: &str, from: usize) -> Vec<String> {
    giganto
        .streams_of(kind)
        .iter()
        .skip(from)
        .flat_map(StreamRecord::lines)
        .collect()
}

/// Waits until the log holds `text`.
async fn wait_for_log(logs: &Logs, text: &str) {
    wait_for(&format!("the log holds {text:?}"), WAIT, || {
        logs.text().contains(text)
    })
    .await;
}

#[cfg(unix)]
#[tokio::test]
async fn start_end_skips_existing_lines_and_a_crash_sends_the_unacknowledged_ones_again()
-> Result<()> {
    let (_pki, giganto, files) = setup()?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1", "a2"])?;
    let state = logs.state();
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload, &state);

    runtime
        .apply(config_start(
            giganto.addr,
            &[("kind_a", &a)],
            StartPosition::End,
        ))
        .await;
    let start = record("kind_a", &a, length(&a));
    wait_for_checkpoint(&state, "kind_a", &start, WAIT).await;
    giganto.withhold_acks(&["kind_a"]);
    append(&a, "a3")?;
    append(&a, "a4")?;
    wait_for_lines(&giganto, "kind_a", &["a3", "a4"]).await;
    assert_eq!(giganto.lines("kind_a"), ["a3", "a4"]);
    // A crash: the runtime is dropped without a shutdown.
    drop(runtime);
    sleep(SETTLE).await;
    assert_eq!(checkpoint(&state, "kind_a"), Some(start));

    giganto.withhold_acks(&[]);
    let streams = giganto.streams_of("kind_a").len();
    let mut runtime = self::runtime(&files.files, &reload, &state);
    runtime
        .apply(config_start(
            giganto.addr,
            &[("kind_a", &a)],
            StartPosition::End,
        ))
        .await;
    wait_for("the new stream receives a3 and a4", WAIT, || {
        lines_from(&giganto, "kind_a", streams) == ["a3", "a4"]
    })
    .await;
    sleep(SETTLE).await;
    assert_eq!(lines_from(&giganto, "kind_a", streams), ["a3", "a4"]);
    runtime.shutdown().await;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn a_restart_after_a_clean_stop_sends_exactly_the_new_lines() -> Result<()> {
    let (_pki, giganto, files) = setup()?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1", "a2"])?;
    let state = logs.state();
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload, &state);
    runtime.apply(config(giganto.addr, &[("kind_a", &a)])).await;
    wait_for_lines(&giganto, "kind_a", &["a1", "a2"]).await;
    runtime.shutdown().await;
    assert_eq!(
        checkpoint(&state, "kind_a"),
        Some(record("kind_a", &a, length(&a)))
    );

    append(&a, "a3")?;
    append(&a, "a4")?;
    let streams = giganto.streams_of("kind_a").len();
    let mut runtime = self::runtime(&files.files, &reload, &state);
    runtime.apply(config(giganto.addr, &[("kind_a", &a)])).await;
    wait_for_lines(&giganto, "kind_a", &["a3", "a4"]).await;
    sleep(SETTLE).await;
    assert_eq!(lines_from(&giganto, "kind_a", streams), ["a3", "a4"]);
    runtime.shutdown().await;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn rename_and_copy_truncate_rotations_send_each_line_once() -> Result<()> {
    let (logs_capture, _guard) = Logs::capture();
    let (_pki, giganto, files) = setup()?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1"])?;
    let state = logs.state();
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload, &state);
    runtime.apply(config(giganto.addr, &[("kind_a", &a)])).await;
    wait_for_lines(&giganto, "kind_a", &["a1"]).await;

    // A rename rotation, with a late write to the renamed file.
    let renamed = logs.path("a.log.1");
    std::fs::rename(&a, &renamed)?;
    std::fs::write(&a, "b1\nb2\nb3\n")?;
    append(&renamed, "a2")?;
    wait_for_lines(&giganto, "kind_a", &["a2", "b1", "b2", "b3"]).await;
    wait_for_checkpoint(&state, "kind_a", &record("kind_a", &a, length(&a)), WAIT).await;

    // A copy-truncate once the reader is at EOF.
    copy_truncate(&a, &["c1"])?;
    wait_for_lines(&giganto, "kind_a", &["c1"]).await;
    wait_for_log(
        &logs_capture,
        &format!(
            "{} for kind_a was truncated; reading it again from its beginning",
            a.display()
        ),
    )
    .await;
    sleep(SETTLE).await;
    assert_eq!(
        giganto.lines("kind_a"),
        ["a1", "a2", "b1", "b2", "b3", "c1"]
    );
    runtime.shutdown().await;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn a_closed_connection_sends_the_unacknowledged_lines_again() -> Result<()> {
    let (_pki, giganto, files) = setup()?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1"])?;
    let state = logs.state();
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload, &state);
    runtime.apply(config(giganto.addr, &[("kind_a", &a)])).await;
    wait_for_lines(&giganto, "kind_a", &["a1"]).await;
    wait_for_checkpoint(&state, "kind_a", &record("kind_a", &a, length(&a)), WAIT).await;

    giganto.withhold_acks(&["kind_a"]);
    append(&a, "a2")?;
    append(&a, "a3")?;
    wait_for_lines(&giganto, "kind_a", &["a2", "a3"]).await;
    giganto.close_connections();
    append(&a, "a4")?;
    wait_for("a new stream carries a4", WAIT, || {
        giganto
            .streams_of("kind_a")
            .get(1)
            .is_some_and(|stream| stream.lines().contains(&"a4".to_string()))
    })
    .await;
    // The new stream starts at the acknowledged position.
    assert_eq!(giganto.streams_of("kind_a")[1].lines(), ["a2", "a3", "a4"]);

    // A stream reopened while the file is unchanged replays only the suffix
    // after the acknowledged position, and then follows new lines.
    giganto.withhold_acks(&[]);
    append(&a, "a5")?;
    wait_for_lines(&giganto, "kind_a", &["a5"]).await;
    wait_for_checkpoint(&state, "kind_a", &record("kind_a", &a, length(&a)), WAIT).await;
    giganto.stop_stream_of("kind_a")?;
    append(&a, "a6")?;
    wait_for("a third stream carries a6", WAIT, || {
        giganto
            .streams_of("kind_a")
            .get(2)
            .is_some_and(|stream| stream.lines().contains(&"a6".to_string()))
    })
    .await;
    sleep(SETTLE).await;
    assert_eq!(giganto.streams_of("kind_a")[2].lines(), ["a6"]);
    assert_eq!(
        giganto
            .lines("kind_a")
            .iter()
            .filter(|line| *line == "a1")
            .count(),
        1
    );
    runtime.shutdown().await;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn an_idle_collector_sends_the_unacknowledged_lines_again() -> Result<()> {
    let (_pki, giganto, files) = setup()?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1"])?;
    let state = logs.state();
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload, &state);
    runtime.apply(config(giganto.addr, &[("kind_a", &a)])).await;
    wait_for_lines(&giganto, "kind_a", &["a1"]).await;
    wait_for_checkpoint(&state, "kind_a", &record("kind_a", &a, length(&a)), WAIT).await;

    // The file stays unchanged after each failure: no later write finds
    // the failed stream.
    giganto.withhold_acks(&["kind_a"]);
    append(&a, "a2")?;
    wait_for_lines(&giganto, "kind_a", &["a2"]).await;
    giganto.stop_stream_of("kind_a")?;
    wait_for("a second stream carries a2", WAIT, || {
        giganto
            .streams_of("kind_a")
            .get(1)
            .is_some_and(|stream| stream.lines() == ["a2"])
    })
    .await;

    giganto.close_connections();
    wait_for("a third stream carries a2", WAIT, || {
        giganto
            .streams_of("kind_a")
            .get(2)
            .is_some_and(|stream| stream.lines() == ["a2"])
    })
    .await;
    assert_eq!(giganto.connections(), 2);

    giganto.withhold_acks(&[]);
    append(&a, "a3")?;
    wait_for_lines(&giganto, "kind_a", &["a3"]).await;
    wait_for_checkpoint(&state, "kind_a", &record("kind_a", &a, length(&a)), WAIT).await;
    runtime.shutdown().await;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn a_delayed_old_ack_does_not_move_a_truncated_files_checkpoint() -> Result<()> {
    let (logs_capture, _guard) = Logs::capture();
    let (_pki, giganto, files) = setup()?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1"])?;
    let state = logs.state();
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload, &state);
    runtime.apply(config(giganto.addr, &[("kind_a", &a)])).await;
    wait_for_lines(&giganto, "kind_a", &["a1"]).await;
    wait_for_checkpoint(&state, "kind_a", &record("kind_a", &a, length(&a)), WAIT).await;

    // Old batches await their ACKs as the file is truncated.
    giganto.hold_acks(&["kind_a"]).await;
    append(&a, "a2 a longer line")?;
    append(&a, "a3 a longer line")?;
    wait_for_lines(
        &giganto,
        "kind_a",
        &["a2 a longer line", "a3 a longer line"],
    )
    .await;
    copy_truncate(&a, &[])?;
    wait_for_log(&logs_capture, "was truncated").await;
    let epoch = record("kind_a", &a, 0);
    wait_for_checkpoint(&state, "kind_a", &epoch, WAIT).await;

    // The old ACKs arrive after the transition: they acknowledge nothing.
    giganto.release_acks().await;
    sleep(SETTLE).await;
    assert_eq!(checkpoint(&state, "kind_a"), Some(epoch));

    // A new line acknowledged moves it.
    append(&a, "b1")?;
    wait_for_lines(&giganto, "kind_a", &["b1"]).await;
    wait_for_checkpoint(&state, "kind_a", &record("kind_a", &a, length(&a)), WAIT).await;
    runtime.shutdown().await;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn a_failing_epoch_save_holds_back_the_new_content() -> Result<()> {
    let (logs_capture, _guard) = Logs::capture();
    let (_pki, giganto, files) = setup()?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1 a longer line", "a2 a longer line"])?;
    let state = logs.state();
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload, &state);
    runtime.apply(config(giganto.addr, &[("kind_a", &a)])).await;
    wait_for_lines(&giganto, "kind_a", &["a2 a longer line"]).await;
    wait_for_checkpoint(&state, "kind_a", &record("kind_a", &a, length(&a)), WAIT).await;

    let obstacle = checkpoint_file(&state, "kind_a").with_extension("json.tmp");
    std::fs::create_dir(&obstacle)?;
    copy_truncate(&a, &["b1"])?;
    wait_for_log(&logs_capture, "was truncated").await;
    // More than two retries of every 3 s.
    sleep(Duration::from_secs(7)).await;
    assert!(!giganto.lines("kind_a").contains(&"b1".to_string()));

    std::fs::remove_dir(&obstacle)?;
    wait_for_lines(&giganto, "kind_a", &["b1"]).await;
    wait_for_checkpoint(&state, "kind_a", &record("kind_a", &a, length(&a)), WAIT).await;
    runtime.shutdown().await;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn new_content_after_a_truncation_survives_a_crash_before_its_first_ack() -> Result<()> {
    let (logs_capture, _guard) = Logs::capture();
    let (_pki, giganto, files) = setup()?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1"])?;
    let state = logs.state();
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload, &state);
    runtime.apply(config(giganto.addr, &[("kind_a", &a)])).await;
    wait_for_lines(&giganto, "kind_a", &["a1"]).await;
    giganto.hold_acks(&["kind_a"]).await;
    append(&a, "a2 a longer line")?;
    append(&a, "a3 a longer line")?;
    wait_for_lines(&giganto, "kind_a", &["a3 a longer line"]).await;
    let old_offset = length(&a);

    copy_truncate(&a, &["b1"])?;
    wait_for_log(&logs_capture, "was truncated").await;
    wait_for_lines(&giganto, "kind_a", &["b1"]).await;
    // New batches await their first ACK: no save carries a position from
    // before the truncation.
    let epoch = record("kind_a", &a, 0);
    let deadline = Instant::now() + SETTLE;
    while Instant::now() < deadline {
        assert_eq!(checkpoint(&state, "kind_a"), Some(epoch.clone()));
        sleep(Duration::from_millis(50)).await;
    }

    // The new content grows past the old offset, and the process crashes.
    let mut count = 2;
    while length(&a) <= old_offset {
        append(&a, &format!("b{count}"))?;
        count += 1;
    }
    let last = format!("b{}", count - 1);
    wait_for_lines(&giganto, "kind_a", &[&last]).await;
    drop(runtime);
    sleep(SETTLE).await;
    assert_eq!(checkpoint(&state, "kind_a"), Some(epoch));

    let streams = giganto.streams_of("kind_a").len();
    giganto.release_acks().await;
    let mut runtime = self::runtime(&files.files, &reload, &state);
    runtime.apply(config(giganto.addr, &[("kind_a", &a)])).await;
    let expected = (1..count)
        .map(|index| format!("b{index}"))
        .collect::<Vec<_>>();
    wait_for("the restart sends the new content", WAIT, || {
        lines_from(&giganto, "kind_a", streams) == expected
    })
    .await;
    runtime.shutdown().await;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn a_new_connection_after_a_truncation_carries_only_new_lines() -> Result<()> {
    let (logs_capture, _guard) = Logs::capture();
    let (_pki, giganto, files) = setup()?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1 a longer line", "a2 a longer line"])?;
    let state = logs.state();
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload, &state);
    runtime.apply(config(giganto.addr, &[("kind_a", &a)])).await;
    wait_for_lines(&giganto, "kind_a", &["a2 a longer line"]).await;
    giganto.withhold_acks(&["kind_a"]);
    append(&a, "a3 a longer line")?;
    wait_for_lines(&giganto, "kind_a", &["a3 a longer line"]).await;

    copy_truncate(&a, &["b1"])?;
    wait_for_log(&logs_capture, "was truncated").await;
    wait_for_lines(&giganto, "kind_a", &["b1"]).await;
    giganto.close_connections();
    append(&a, "b2")?;
    wait_for("a new stream carries b2", WAIT, || {
        giganto
            .streams_of("kind_a")
            .get(1)
            .is_some_and(|stream| stream.lines().contains(&"b2".to_string()))
    })
    .await;
    assert_eq!(giganto.streams_of("kind_a")[1].lines(), ["b1", "b2"]);
    giganto.withhold_acks(&[]);
    runtime.shutdown().await;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn a_file_truncated_while_stopped_saves_its_epoch_before_sending() -> Result<()> {
    let (logs_capture, _guard) = Logs::capture();
    let (_pki, giganto, files) = setup()?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1 a longer line", "a2 a longer line"])?;
    let state = logs.state();
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload, &state);
    runtime.apply(config(giganto.addr, &[("kind_a", &a)])).await;
    wait_for_lines(&giganto, "kind_a", &["a2 a longer line"]).await;
    runtime.shutdown().await;

    copy_truncate(&a, &["b1"])?;
    // The epoch's save fails at first: nothing is sent until it lands.
    let obstacle = checkpoint_file(&state, "kind_a").with_extension("json.tmp");
    std::fs::create_dir(&obstacle)?;
    giganto.withhold_acks(&["kind_a"]);
    let streams = giganto.streams_of("kind_a").len();
    let opened = giganto.streams().len();
    let mut runtime = self::runtime(&files.files, &reload, &state);
    runtime.apply(config(giganto.addr, &[("kind_a", &a)])).await;
    wait_for_log(&logs_capture, "was truncated").await;
    sleep(Duration::from_secs(4)).await;
    assert_eq!(giganto.streams().len(), opened, "no stream is opened");

    std::fs::remove_dir(&obstacle)?;
    wait_for_lines(&giganto, "kind_a", &["b1"]).await;
    assert_eq!(checkpoint(&state, "kind_a"), Some(record("kind_a", &a, 0)));
    assert_eq!(lines_from(&giganto, "kind_a", streams), ["b1"]);
    giganto.withhold_acks(&[]);
    runtime.shutdown().await;
    Ok(())
}

/// With the first save of the starting position failing, nothing is sent
/// until it lands; after a crash before the first data ACK, the lines
/// appended since are sent.
#[cfg(unix)]
async fn initial_save_failure_then_crash(corrupt: bool) -> Result<()> {
    let (logs_capture, _guard) = Logs::capture();
    let (_pki, giganto, files) = setup()?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1"])?;
    let state = logs.state();
    let file = checkpoint_file(&state, "kind_a");
    std::fs::create_dir_all(file.parent().context("a parent")?)?;
    if corrupt {
        std::fs::write(&file, b"{")?;
    }
    let obstacle = file.with_extension("json.tmp");
    std::fs::create_dir(&obstacle)?;
    giganto.withhold_acks(&["kind_a"]);
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload, &state);
    runtime
        .apply(config_start(
            giganto.addr,
            &[("kind_a", &a)],
            StartPosition::End,
        ))
        .await;
    // The starting position is chosen before its first save fails.
    wait_for_log(&logs_capture, "Cannot save the checkpoint of kind_a").await;
    append(&a, "a2")?;
    sleep(Duration::from_secs(7)).await;
    assert!(giganto.streams().is_empty(), "{:?}", giganto.streams());

    std::fs::remove_dir(&obstacle)?;
    // The starting position chosen before the save first failed.
    wait_for_checkpoint(&state, "kind_a", &record("kind_a", &a, 3), WAIT).await;
    wait_for_lines(&giganto, "kind_a", &["a2"]).await;
    append(&a, "a3")?;
    wait_for_lines(&giganto, "kind_a", &["a3"]).await;
    drop(runtime);
    sleep(SETTLE).await;

    giganto.withhold_acks(&[]);
    let streams = giganto.streams_of("kind_a").len();
    let mut runtime = self::runtime(&files.files, &reload, &state);
    runtime
        .apply(config_start(
            giganto.addr,
            &[("kind_a", &a)],
            StartPosition::End,
        ))
        .await;
    wait_for("the restart sends a2 and a3", WAIT, || {
        lines_from(&giganto, "kind_a", streams) == ["a2", "a3"]
    })
    .await;
    assert!(!giganto.lines("kind_a").contains(&"a1".to_string()));
    runtime.shutdown().await;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn a_failing_initial_save_holds_back_start_end() -> Result<()> {
    initial_save_failure_then_crash(false).await
}

#[cfg(unix)]
#[tokio::test]
async fn a_failing_initial_save_holds_back_a_corrupt_checkpoints_replacement() -> Result<()> {
    initial_save_failure_then_crash(true).await
}

#[tokio::test]
async fn timestamps_strictly_increase_within_a_batch() -> Result<()> {
    let (_pki, giganto, files) = setup()?;
    let logs = LogFiles::new()?;
    let lines = (0..500)
        .map(|index| format!("l{index}"))
        .collect::<Vec<_>>();
    let a = logs.create(
        "a.log",
        &lines.iter().map(String::as_str).collect::<Vec<_>>(),
    )?;
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload, &logs.state());
    runtime.apply(config(giganto.addr, &[("kind_a", &a)])).await;
    wait_for("every line arrives", WAIT, || {
        giganto.lines("kind_a").len() == lines.len()
    })
    .await;
    let timestamps = giganto
        .streams_of("kind_a")
        .iter()
        .flat_map(|stream| stream.timestamps.clone())
        .collect::<Vec<_>>();
    assert_eq!(timestamps.len(), lines.len());
    assert!(timestamps.windows(2).all(|pair| pair[0] < pair[1]));
    runtime.shutdown().await;
    Ok(())
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_symlink_into_proc_is_refused() -> Result<()> {
    let (logs_capture, _guard) = Logs::capture();
    let (_pki, giganto, files) = setup()?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1"])?;
    let link = logs.path("status.log");
    std::os::unix::fs::symlink("/proc/self/status", &link)?;
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload, &logs.state());
    runtime
        .apply(config(giganto.addr, &[("kind_a", &a), ("kind_p", &link)]))
        .await;
    wait_for_lines(&giganto, "kind_a", &["a1"]).await;
    let expected = format!(
        "Collector kind_p for {}: the file lies under the refused directory /proc",
        link.display()
    );
    wait_for_log(&logs_capture, &expected).await;
    sleep(SETTLE).await;
    assert!(giganto.streams_of("kind_p").is_empty());
    assert_eq!(giganto.lines("kind_p"), Vec::<String>::new());
    runtime.shutdown().await;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn a_blocked_write_does_not_hold_back_the_release_of_a_rotated_away_file() -> Result<()> {
    let (_pki, giganto, files) = setup()?;
    let logs = LogFiles::new()?;
    let a = logs.create("a.log", &["a1"])?;
    let state = logs.state();
    let reload = ReloadSignal::new();
    let mut runtime = runtime(&files.files, &reload, &state);
    runtime.apply(config(giganto.addr, &[("kind_a", &a)])).await;
    wait_for_lines(&giganto, "kind_a", &["a1"]).await;
    wait_for_checkpoint(&state, "kind_a", &record("kind_a", &a, length(&a)), WAIT).await;

    // The ACK of the last line of the file rotated away is held back, so
    // the file is held once the collector reads the new one.
    giganto.hold_acks(&["kind_a"]).await;
    append(&a, "a2")?;
    wait_for_lines(&giganto, "kind_a", &["a2"]).await;
    giganto.pause_reading_after("kind_a", "b1");
    let renamed = logs.path("a.log.1");
    std::fs::rename(&a, &renamed)?;
    std::fs::write(&a, "b1\n")?;
    wait_for_lines(&giganto, "kind_a", &["b1"]).await;
    assert!(is_open(&renamed));

    // A batch larger than the stream's receive window, with nothing after
    // it: its write waits for the server, which reads no further, and the
    // reader waits at the end of the file. The reader finds the lines at
    // its next check, at most 3 seconds later.
    let filler = "x".repeat(3400);
    let mut lines = (0..1000)
        .map(|index| format!("c{index:04}{filler}"))
        .collect::<Vec<_>>()
        .join("\n");
    lines.push('\n');
    std::fs::OpenOptions::new()
        .append(true)
        .open(&a)
        .and_then(|mut file| std::io::Write::write_all(&mut file, lines.as_bytes()))?;
    sleep(Duration::from_secs(3) + SETTLE).await;

    // The held ACKs arrive while the write is still blocked: the
    // acknowledged position leaves the rotated-away file, which is
    // released within about three seconds.
    giganto.release_acks().await;
    let released = Instant::now();
    wait_for(
        "the rotated-away file is released",
        Duration::from_millis(4500),
        || !is_open(&renamed),
    )
    .await;
    assert_eq!(giganto.lines("kind_a"), ["a1", "a2", "b1"]);
    sleep(Duration::from_secs(3).saturating_sub(released.elapsed())).await;
    assert_eq!(
        giganto.lines("kind_a"),
        ["a1", "a2", "b1"],
        "the write stays blocked beyond three seconds"
    );

    giganto.resume_reading();
    wait_for("the batch arrives", WAIT, || {
        giganto.lines("kind_a").len() == 1003
    })
    .await;
    wait_for_checkpoint(&state, "kind_a", &record("kind_a", &a, length(&a)), WAIT).await;
    runtime.shutdown().await;
    Ok(())
}

/// The journal collector against a fake journalctl.
#[cfg(target_os = "linux")]
mod journal {
    use std::fmt::Write as _;
    use std::io::Write as _;

    use giganto_client::ingest::log::OpLogLevel;
    use serde_json::{Value, json};

    use super::*;
    use crate::support::giganto::{JOURNAL, op_log_header};

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

    /// The `n`th test entry, with `fields` besides its position.
    fn entry_with(n: u64, fields: &Value) -> Value {
        let mut entry = json!({
            "__CURSOR": cursor(n),
            "__REALTIME_TIMESTAMP": time(n).to_string(),
            "__MONOTONIC_TIMESTAMP": n.to_string(),
            "__SEQNUM": n.to_string(),
            "__SEQNUM_ID": SEQNUM_ID,
            "_BOOT_ID": BOOT_ID,
            "MESSAGE": message(n),
        });
        for (key, value) in fields.as_object().expect("an object") {
            entry[key] = value.clone();
        }
        entry
    }

    /// The `n`th test entry, of `unit`.
    fn entry(n: u64, unit: &str) -> Value {
        entry_with(n, &json!({ "_SYSTEMD_UNIT": unit }))
    }

    fn message(n: u64) -> String {
        format!("message {n}")
    }

    fn messages(range: impl IntoIterator<Item = u64>) -> Vec<String> {
        range.into_iter().map(message).collect()
    }

    /// A fake journalctl in a directory of its own, with a machine-ID file
    /// and a journal root holding a readable `system.journal`.
    struct Fake {
        dir: TempDir,
    }

    impl Fake {
        fn new() -> Result<Self> {
            let dir = tempfile::tempdir()?;
            let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/journalctl");
            std::os::unix::fs::symlink(script, dir.path().join("journalctl"))?;
            std::fs::write(dir.path().join("entries"), b"")?;
            std::fs::write(dir.path().join("machine-id"), format!("{MACHINE_ID}\n"))?;
            let journal = dir.path().join("journal").join(MACHINE_ID);
            std::fs::create_dir_all(&journal)?;
            std::fs::write(journal.join("system.journal"), b"")?;
            Ok(Self { dir })
        }

        fn path(&self, name: &str) -> PathBuf {
            self.dir.path().join(name)
        }

        fn push(&self, entries: &[Value]) -> Result<()> {
            let text = entries.iter().fold(String::new(), |mut text, entry| {
                let _ = writeln!(text, "{entry}");
                text
            });
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(self.path("entries"))?;
            file.write_all(text.as_bytes())?;
            Ok(())
        }

        /// Replaces the journal by `entries`, as a vacuum removing entries
        /// does; a running journalctl keeps reading the replaced one.
        fn rewrite(&self, entries: &[Value]) -> Result<()> {
            let text = entries.iter().fold(String::new(), |mut text, entry| {
                let _ = writeln!(text, "{entry}");
                text
            });
            let new = self.path("entries.new");
            std::fs::write(&new, text)?;
            std::fs::rename(new, self.path("entries"))?;
            Ok(())
        }

        /// The arguments of every journalctl run, past the common ones.
        fn args(&self) -> Vec<String> {
            std::fs::read_to_string(self.path("args"))
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
            std::fs::read_to_string(self.path("pids"))
                .unwrap_or_default()
                .lines()
                .map(|line| line.parse().expect("a pid"))
                .collect()
        }

        /// The process ID of the last journalctl started.
        fn last_pid(&self) -> u32 {
            *self.pids().last().expect("journalctl ran")
        }

        fn runtime(
            &self,
            files: &TlsFiles,
            reload: &ReloadSignal,
            state_dir: &Path,
        ) -> CollectorRuntime {
            runtime(files, reload, state_dir).with_journal_paths(
                self.path("journalctl"),
                self.path("machine-id"),
                self.path("journal"),
            )
        }
    }

    fn running(pid: u32) -> bool {
        Path::new(&format!("/proc/{pid}")).exists()
    }

    /// A configuration of the journal collector and `logs` collectors.
    fn journal_config(addr: SocketAddr, logs: &[(&str, &Path)]) -> RemoteConfig {
        let mut config = config(addr, logs);
        config.collectors.push(CollectorConfig::Journal);
        config
    }

    fn journal_file(state_dir: &Path) -> PathBuf {
        state_dir.join("checkpoints").join("journal.json")
    }

    /// The cursor the journal checkpoint holds, if it can be read.
    fn checkpoint_cursor(state_dir: &Path) -> Option<String> {
        let bytes = std::fs::read(journal_file(state_dir)).ok()?;
        let value = serde_json::from_slice::<Value>(&bytes).ok()?;
        Some(value["cursor"].as_str()?.to_string())
    }

    async fn wait_for_cursor(state_dir: &Path, n: u64) {
        let expected = cursor(n);
        wait_for(
            &format!("the journal checkpoint is at entry {n}"),
            WAIT,
            || checkpoint_cursor(state_dir).as_deref() == Some(expected.as_str()),
        )
        .await;
    }

    async fn wait_for_messages(giganto: &Giganto, range: impl IntoIterator<Item = u64>) {
        let expected = messages(range);
        let lines = expected.iter().map(String::as_str).collect::<Vec<_>>();
        wait_for_lines(giganto, JOURNAL, &lines).await;
    }

    #[tokio::test]
    async fn the_journal_stream_shares_the_connection_with_log_collectors() -> Result<()> {
        let (logs_capture, _guard) = Logs::capture();
        let (_pki, giganto, files) = setup()?;
        let fake = Fake::new()?;
        fake.push(&[
            entry_with(1, &json!({ "_SYSTEMD_UNIT": KEPT, "PRIORITY": "3" })),
            entry(2, DROPPED),
            entry_with(
                3,
                &json!({
                    "_SYSTEMD_UNIT": "docker.service",
                    "CONTAINER_NAME": "clumit-security-db",
                    "PRIORITY": "4",
                }),
            ),
            entry_with(
                4,
                &json!({
                    "_SYSTEMD_UNIT": "init.scope",
                    "_PID": "1",
                    "UNIT": "clumit-security-b.service",
                }),
            ),
            // A forged container name.
            entry_with(
                5,
                &json!({ "_SYSTEMD_UNIT": "session-1.scope", "CONTAINER_NAME": "clumit-security-db" }),
            ),
        ])?;
        let logs = LogFiles::new()?;
        let a = logs.create("a.log", &["a1"])?;
        let reload = ReloadSignal::new();
        let mut runtime = fake.runtime(&files.files, &reload, &logs.state());

        runtime
            .apply(journal_config(giganto.addr, &[("kind_a", &a)]))
            .await;
        wait_for_messages(&giganto, [1, 3, 4]).await;
        wait_for_lines(&giganto, "kind_a", &["a1"]).await;
        assert!(
            logs_capture
                .text()
                .contains("Started the journal collector")
        );

        assert_eq!(giganto.connections(), 1);
        let streams = giganto.streams();
        assert_eq!(streams.len(), 2);
        assert!(streams.iter().all(|stream| stream.connection == 0));
        let journal = &giganto.streams_of(JOURNAL)[0];
        assert_eq!(journal.header, op_log_header());
        assert_eq!(giganto.streams_of("kind_a")[0].header, log_header());
        let decoded = journal
            .op_logs
            .iter()
            .map(|op_log| {
                (
                    op_log.sensor.as_str(),
                    op_log.service_name.as_str(),
                    op_log.log_level.clone(),
                    op_log.contents.as_str(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            decoded,
            [
                (
                    "",
                    "clumit-security/unit/clumit-security-a.service",
                    OpLogLevel::Error,
                    "message 1"
                ),
                (
                    "",
                    "clumit-security/container/clumit-security-db",
                    OpLogLevel::Warn,
                    "message 3"
                ),
                (
                    "",
                    "clumit-security/systemd/clumit-security-b.service",
                    OpLogLevel::Info,
                    "message 4"
                ),
            ]
        );
        // Stamped from the entries' times.
        let stamps = [1, 3, 4]
            .map(|n| i64::try_from(time(n) * 1000).expect("fits"))
            .to_vec();
        assert_eq!(journal.timestamps, stamps);

        // Once everything written is acknowledged, the checkpoint moves past
        // the entry dropped after the last record.
        wait_for_cursor(&logs.state(), 5).await;

        runtime.shutdown().await;
        assert!(giganto.streams().iter().all(|stream| stream.close_marker));
        assert!(
            logs_capture
                .text()
                .contains("Stopped the journal collector with close ACK Received")
        );
        assert!(!running(fake.last_pid()), "journalctl is stopped");
        wait_for_cursor(&logs.state(), 5).await;
        Ok(())
    }

    #[tokio::test]
    async fn a_dropped_stream_and_a_lost_connection_lose_no_entry() -> Result<()> {
        let (_pki, giganto, files) = setup()?;
        let fake = Fake::new()?;
        fake.push(&[entry(1, KEPT), entry(2, KEPT), entry(3, KEPT)])?;
        let logs = LogFiles::new()?;
        let reload = ReloadSignal::new();
        let mut runtime = fake.runtime(&files.files, &reload, &logs.state());

        runtime.apply(journal_config(giganto.addr, &[])).await;
        wait_for_messages(&giganto, 1..=3).await;
        wait_for_cursor(&logs.state(), 3).await;
        let follow = fake.last_pid();
        assert_eq!(fake.args().len(), 2);

        // The server stops the stream: journalctl is stopped while it is
        // down, and the new stream starts catch-up from the acknowledged
        // entry.
        giganto.stop_stream_of(JOURNAL)?;
        wait_for("the stream is replaced", WAIT, || {
            giganto.streams_of(JOURNAL).len() == 2
        })
        .await;
        assert!(!running(follow), "journalctl was stopped and reaped");
        wait_for("journalctl runs again", WAIT, || fake.args().len() >= 4).await;
        assert_eq!(
            fake.args()[2..4],
            [
                format!("--after-cursor={}", cursor(3)),
                format!("--follow --lines=all --after-cursor={}", cursor(3)),
            ]
        );
        fake.push(&[entry(4, KEPT)])?;
        wait_for_messages(&giganto, [4]).await;
        assert_eq!(giganto.streams_of(JOURNAL)[1].lines(), messages([4]));
        wait_for_cursor(&logs.state(), 4).await;

        // The connection is lost.
        let follow = fake.last_pid();
        giganto.close_connections();
        wait_for("a new connection carries the stream", WAIT, || {
            giganto
                .streams_of(JOURNAL)
                .last()
                .is_some_and(|stream| stream.connection == 1)
        })
        .await;
        assert!(!running(follow), "journalctl was stopped and reaped");
        fake.push(&[entry(5, KEPT)])?;
        wait_for_messages(&giganto, [5]).await;
        let received = giganto.lines(JOURNAL);
        for expected in messages(1..=5) {
            assert!(received.contains(&expected), "{expected} in {received:?}");
        }
        // Everything acknowledged before a drop is not sent again.
        assert_eq!(
            received.iter().filter(|line| *line == "message 1").count(),
            1,
            "{received:?}"
        );

        runtime.shutdown().await;
        wait_for_cursor(&logs.state(), 5).await;
        Ok(())
    }

    #[tokio::test]
    async fn unacknowledged_entries_are_sent_again_on_a_new_stream() -> Result<()> {
        let (_pki, giganto, files) = setup()?;
        let fake = Fake::new()?;
        fake.push(&[entry(1, KEPT), entry(2, KEPT)])?;
        let logs = LogFiles::new()?;
        let reload = ReloadSignal::new();
        let mut runtime = fake.runtime(&files.files, &reload, &logs.state());
        giganto.hold_acks(&[JOURNAL]).await;

        runtime.apply(journal_config(giganto.addr, &[])).await;
        wait_for_messages(&giganto, 1..=2).await;
        sleep(SETTLE).await;
        assert_eq!(checkpoint_cursor(&logs.state()), None);

        // Nothing is acknowledged: the new stream reads from the oldest
        // entry.
        giganto.stop_stream_of(JOURNAL)?;
        wait_for("the entries are sent again", WAIT, || {
            giganto
                .streams_of(JOURNAL)
                .get(1)
                .is_some_and(|stream| stream.lines() == messages(1..=2))
        })
        .await;
        assert!(fake.args().contains(&String::new()));
        assert_eq!(
            fake.args().iter().filter(|args| args.is_empty()).count(),
            2,
            "{:?}",
            fake.args()
        );
        giganto.release_acks().await;
        wait_for_cursor(&logs.state(), 2).await;

        runtime.shutdown().await;
        Ok(())
    }

    #[tokio::test]
    async fn a_follow_exit_restarts_journalctl_on_the_same_stream() -> Result<()> {
        let (logs_capture, _guard) = Logs::capture();
        let (_pki, giganto, files) = setup()?;
        let fake = Fake::new()?;
        fake.push(&[entry(1, KEPT)])?;
        let logs = LogFiles::new()?;
        let reload = ReloadSignal::new();
        let mut runtime = fake.runtime(&files.files, &reload, &logs.state());

        runtime.apply(journal_config(giganto.addr, &[])).await;
        wait_for_messages(&giganto, [1]).await;
        wait_for("journalctl follows", WAIT, || fake.args().len() == 2).await;
        fake.push(&[entry(2, KEPT), entry(3, DROPPED)])?;
        wait_for_messages(&giganto, [2]).await;

        let status = std::process::Command::new("kill")
            .args(["-KILL", &fake.last_pid().to_string()])
            .status()?;
        assert!(status.success());
        wait_for("journalctl is started again", WAIT, || {
            fake.args().len() >= 4
        })
        .await;
        assert_eq!(
            fake.args()[2..4],
            [
                format!("--after-cursor={}", cursor(3)),
                format!("--follow --lines=all --after-cursor={}", cursor(3)),
            ]
        );
        fake.push(&[entry(4, KEPT)])?;
        wait_for_messages(&giganto, [4]).await;
        let streams = giganto.streams_of(JOURNAL);
        assert_eq!(streams.len(), 1, "the stream is kept");
        assert_eq!(streams[0].lines(), messages([1, 2, 4]));
        assert!(streams[0].ended.is_none());
        assert_eq!(
            logs_capture
                .text()
                .matches("journalctl ended with signal: 9 (SIGKILL) while following the journal")
                .count(),
            1
        );

        runtime.shutdown().await;
        Ok(())
    }

    #[tokio::test]
    async fn applies_keep_remove_and_add_the_journal_collector() -> Result<()> {
        let (logs_capture, _guard) = Logs::capture();
        let (_pki, giganto, files) = setup()?;
        let fake = Fake::new()?;
        fake.push(&[entry(1, KEPT), entry(2, KEPT)])?;
        let logs = LogFiles::new()?;
        let a = logs.create("a.log", &["a1"])?;
        let b = logs.create("b.log", &["b1"])?;
        let reload = ReloadSignal::new();
        let mut runtime = fake.runtime(&files.files, &reload, &logs.state());

        runtime
            .apply(journal_config(giganto.addr, &[("kind_a", &a)]))
            .await;
        wait_for_messages(&giganto, 1..=2).await;
        wait_for_cursor(&logs.state(), 2).await;
        wait_for("journalctl follows", WAIT, || fake.args().len() == 2).await;
        let follow = fake.last_pid();

        // Keeping it restarts nothing.
        runtime
            .apply(journal_config(
                giganto.addr,
                &[("kind_a", &a), ("kind_b", &b)],
            ))
            .await;
        wait_for_lines(&giganto, "kind_b", &["b1"]).await;
        sleep(SETTLE).await;
        assert_eq!(fake.pids(), fake.pids()[..2]);
        assert!(running(follow));
        let journal = giganto.streams_of(JOURNAL);
        assert_eq!(journal.len(), 1);
        assert!(journal[0].ended.is_none() && !journal[0].close_marker);
        assert!(
            logs_capture
                .text()
                .contains("Applied a configuration with 3 collectors: 1 started, 0 stopped")
        );

        // Removing it stops it without a save.
        giganto.hold_acks(&[JOURNAL]).await;
        fake.push(&[entry(3, KEPT)])?;
        wait_for_messages(&giganto, [3]).await;
        runtime
            .apply(config(giganto.addr, &[("kind_a", &a), ("kind_b", &b)]))
            .await;
        let text = logs_capture.text();
        assert!(
            text.contains("Applied a configuration with 2 collectors: 0 started, 1 stopped"),
            "{text}"
        );
        assert!(
            text.contains("Stopped the journal collector with close ACK Received"),
            "{text}"
        );
        assert!(giganto.streams_of(JOURNAL)[0].close_marker);
        assert!(!running(follow));
        sleep(SETTLE).await;
        assert_eq!(checkpoint_cursor(&logs.state()), Some(cursor(2)));
        assert_eq!(giganto.streams_of("kind_a").len(), 1);

        // Adding it again resumes from its checkpoint.
        giganto.release_acks().await;
        runtime
            .apply(journal_config(
                giganto.addr,
                &[("kind_a", &a), ("kind_b", &b)],
            ))
            .await;
        wait_for("a new stream carries entry 3", WAIT, || {
            giganto
                .streams_of(JOURNAL)
                .get(1)
                .is_some_and(|stream| stream.lines() == messages([3]))
        })
        .await;
        assert_eq!(fake.args()[2], format!("--after-cursor={}", cursor(2)));
        wait_for_cursor(&logs.state(), 3).await;

        runtime.shutdown().await;
        Ok(())
    }

    #[tokio::test]
    async fn a_corrupt_checkpoint_starts_after_the_saved_tail() -> Result<()> {
        let (logs_capture, _guard) = Logs::capture();
        let (_pki, giganto, files) = setup()?;
        let fake = Fake::new()?;
        fake.push(&[entry(1, KEPT), entry(2, KEPT), entry(3, DROPPED)])?;
        let logs = LogFiles::new()?;
        let reload = ReloadSignal::new();
        let mut runtime = fake.runtime(&files.files, &reload, &logs.state());
        let checkpoints = logs.state().join("checkpoints");
        std::fs::create_dir(&checkpoints)?;
        std::fs::write(journal_file(&logs.state()), b"garbage")?;
        // The save of the tail fails while a directory is in the way.
        let tmp = checkpoints.join("journal.json.tmp");
        std::fs::create_dir(&tmp)?;

        runtime.apply(journal_config(giganto.addr, &[])).await;
        wait_for("the tail is read", WAIT, || fake.args().len() == 1).await;
        assert_eq!(fake.args(), ["--lines=1"]);
        sleep(SETTLE).await;
        assert!(giganto.streams_of(JOURNAL).is_empty(), "nothing is sent");
        assert_eq!(fake.args().len(), 1);

        std::fs::remove_dir(&tmp)?;
        wait_for_cursor(&logs.state(), 3).await;
        wait_for("the stream opens", WAIT, || {
            !giganto.streams_of(JOURNAL).is_empty()
        })
        .await;
        wait_for("journalctl follows", WAIT, || fake.args().len() == 3).await;
        fake.push(&[entry(4, KEPT)])?;
        wait_for_messages(&giganto, [4]).await;
        assert_eq!(giganto.lines(JOURNAL), messages([4]));
        assert_eq!(
            fake.args()[1..3],
            [
                format!("--after-cursor={}", cursor(3)),
                format!("--follow --lines=all --after-cursor={}", cursor(3)),
            ]
        );
        let text = logs_capture.text();
        assert_eq!(
            text.matches("unsent earlier entries may be skipped")
                .count(),
            1,
            "{text}"
        );

        runtime.shutdown().await;
        Ok(())
    }

    #[tokio::test]
    async fn journalctl_waits_for_the_stream() -> Result<()> {
        let (_pki, giganto, files) = setup()?;
        let fake = Fake::new()?;
        fake.push(&[entry(1, KEPT)])?;
        let logs = LogFiles::new()?;
        let silent = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        let reload = ReloadSignal::new();
        let mut runtime = fake.runtime(&files.files, &reload, &logs.state());

        runtime
            .apply(journal_config(silent.local_addr()?, &[]))
            .await;
        sleep(SETTLE).await;
        assert_eq!(
            fake.args(),
            Vec::<String>::new(),
            "no stream, no journalctl"
        );

        runtime.apply(journal_config(giganto.addr, &[])).await;
        wait_for_messages(&giganto, [1]).await;
        assert_eq!(fake.args()[0], "");
        runtime.shutdown().await;
        Ok(())
    }

    #[tokio::test]
    async fn journalctl_waits_for_the_access_check() -> Result<()> {
        let (logs_capture, _guard) = Logs::capture();
        let (_pki, giganto, files) = setup()?;
        let fake = Fake::new()?;
        fake.push(&[entry(1, KEPT)])?;
        std::fs::write(fake.path("machine-id"), b"x\n")?;
        let logs = LogFiles::new()?;
        let reload = ReloadSignal::new();
        let mut runtime = fake.runtime(&files.files, &reload, &logs.state());

        runtime.apply(journal_config(giganto.addr, &[])).await;
        let error = "cannot read the system journal; is the unit in group adm?";
        wait_for("the access error is logged", WAIT, || {
            logs_capture.text().contains(error)
        })
        .await;
        sleep(SETTLE).await;
        assert_eq!(logs_capture.text().matches(error).count(), 1);
        assert_eq!(fake.args(), Vec::<String>::new(), "journalctl does not run");
        assert!(giganto.streams_of(JOURNAL).is_empty(), "no stream opens");

        std::fs::write(fake.path("machine-id"), format!("{MACHINE_ID}\n"))?;
        wait_for_messages(&giganto, [1]).await;
        assert!(
            logs_capture
                .text()
                .contains("Journal collector: the system journal is readable")
        );
        runtime.shutdown().await;
        Ok(())
    }

    #[tokio::test]
    async fn an_address_change_moves_the_journal_stream() -> Result<()> {
        let pki = Pki::new()?;
        let first = Giganto::start(&pki)?;
        let second = Giganto::start(&pki)?;
        let files = Files::new(&pki, &pki.client()?)?;
        let fake = Fake::new()?;
        fake.push(&[entry(1, KEPT)])?;
        let logs = LogFiles::new()?;
        let reload = ReloadSignal::new();
        let mut runtime = fake.runtime(&files.files, &reload, &logs.state());

        runtime.apply(journal_config(first.addr, &[])).await;
        wait_for_messages(&first, [1]).await;
        wait_for_cursor(&logs.state(), 1).await;
        runtime.apply(journal_config(second.addr, &[])).await;
        wait_for("the stream moves", WAIT, || {
            !second.streams_of(JOURNAL).is_empty()
        })
        .await;
        fake.push(&[entry(2, KEPT)])?;
        wait_for_messages(&second, [2]).await;
        assert_eq!(second.lines(JOURNAL), messages([2]));
        assert!(!first.streams_of(JOURNAL)[0].close_marker);

        runtime.shutdown().await;
        assert!(second.streams_of(JOURNAL)[0].close_marker);
        Ok(())
    }

    #[tokio::test]
    async fn shutdown_saves_what_the_close_ack_acknowledges() -> Result<()> {
        let (_pki, giganto, files) = setup()?;
        let fake = Fake::new()?;
        fake.push(&[entry(1, KEPT), entry(2, KEPT), entry(3, KEPT)])?;
        let logs = LogFiles::new()?;
        let reload = ReloadSignal::new();
        let mut runtime = fake.runtime(&files.files, &reload, &logs.state());
        giganto.withhold_acks(&[JOURNAL]);

        runtime.apply(journal_config(giganto.addr, &[])).await;
        wait_for_messages(&giganto, 1..=3).await;
        sleep(SETTLE).await;
        assert_eq!(checkpoint_cursor(&logs.state()), None);
        let follow = fake.last_pid();

        runtime.shutdown().await;
        assert!(giganto.streams_of(JOURNAL)[0].close_marker);
        assert!(!running(follow));
        assert_eq!(checkpoint_cursor(&logs.state()), Some(cursor(3)));
        let saved = serde_json::from_slice::<Value>(&std::fs::read(journal_file(&logs.state()))?)?;
        assert_eq!(
            saved,
            json!({
                "type": "journal",
                "cursor": cursor(3),
                "seqnum_id": SEQNUM_ID,
                "seqnum": 3,
                "realtime_us": time(3),
            })
        );
        Ok(())
    }

    /// The `n`th test entry, of the kept unit, written at `realtime_us`.
    fn timed(n: u64, realtime_us: u64) -> Value {
        entry_with(
            n,
            &json!({ "_SYSTEMD_UNIT": KEPT, "__REALTIME_TIMESTAMP": realtime_us.to_string() }),
        )
    }

    /// The `n`th test entry, of the kept unit, without `field`.
    fn without(n: u64, field: &str) -> Value {
        let mut entry = entry(n, KEPT);
        entry
            .as_object_mut()
            .expect("an object")
            .remove(field)
            .expect("the field");
        entry
    }

    /// The `n`th test entry, of the kept unit, whose line is longer than
    /// 1 MiB.
    fn long(n: u64) -> Value {
        entry_with(
            n,
            &json!({ "_SYSTEMD_UNIT": KEPT, "MESSAGE": "x".repeat(1024 * 1024) }),
        )
    }

    /// The stamp of an entry written at `realtime_us`.
    fn stamp(realtime_us: u64) -> i64 {
        i64::try_from(realtime_us * 1000).expect("fits")
    }

    /// Asserts that the stamps of every journal stream strictly increase.
    fn assert_increasing_stamps(giganto: &Giganto) {
        for stream in giganto.streams_of(JOURNAL) {
            assert!(
                stream.timestamps.windows(2).all(|pair| pair[0] < pair[1]),
                "{:?}",
                stream.timestamps
            );
        }
    }

    /// The bytes process `pid` has written.
    fn written(pid: u32) -> Result<u64> {
        let io = std::fs::read_to_string(format!("/proc/{pid}/io"))?;
        io.lines()
            .find_map(|line| line.strip_prefix("wchar: "))
            .context("a wchar line")?
            .parse()
            .context("a byte count")
    }

    /// Waits until the journal streams carry `count` records.
    async fn wait_for_count(giganto: &Giganto, count: usize) {
        wait_for(&format!("{count} journal records arrive"), WAIT, || {
            giganto.lines(JOURNAL).len() >= count
        })
        .await;
    }

    /// What the lost-interval warning says of the entries at `a` and `b`.
    const GAP: &str = "may be missing: removed before they were sent, or lost by journald";
    const UNAVAILABLE: &str =
        "journal sequence numbers are unavailable; the lost-interval check is skipped";

    /// The time of the `n`th test entry as the lost-interval warning names
    /// it.
    fn named(n: u64) -> String {
        format!("2023-11-14T22:13:20.{n:06}Z")
    }

    fn gap(a: &str, b: &str) -> String {
        format!("journal entries between {a} and {b} {GAP}")
    }

    /// Saves a journal checkpoint at the `n`th test entry, with `seqnum`.
    fn save_checkpoint(state_dir: &Path, n: u64, seqnum: Option<u64>) -> Result<()> {
        std::fs::create_dir_all(state_dir.join("checkpoints"))?;
        let record = json!({
            "type": "journal",
            "cursor": cursor(n),
            "seqnum_id": SEQNUM_ID,
            "seqnum": seqnum,
            "realtime_us": time(n),
        });
        std::fs::write(journal_file(state_dir), format!("{record}\n"))?;
        Ok(())
    }

    /// A journal collector reading a fake journalctl, and what it logs.
    struct Run {
        capture: Logs,
        _guard: tracing::subscriber::DefaultGuard,
        _pki: Pki,
        giganto: Giganto,
        _files: Files,
        fake: Fake,
        logs: LogFiles,
        runtime: CollectorRuntime,
    }

    impl Run {
        /// Starts the collector over `entries`, from a checkpoint at the
        /// `n`th test entry with sequence number `seqnum` if `saved` is
        /// `Some((n, seqnum))`.
        async fn start(saved: Option<(u64, Option<u64>)>, entries: &[Value]) -> Result<Self> {
            let (capture, guard) = Logs::capture();
            let (pki, giganto, files) = setup()?;
            let fake = Fake::new()?;
            fake.push(entries)?;
            let logs = LogFiles::new()?;
            if let Some((n, seqnum)) = saved {
                save_checkpoint(&logs.state(), n, seqnum)?;
            }
            let reload = ReloadSignal::new();
            let mut runtime = fake.runtime(&files.files, &reload, &logs.state());
            runtime.apply(journal_config(giganto.addr, &[])).await;
            Ok(Self {
                capture,
                _guard: guard,
                _pki: pki,
                giganto,
                _files: files,
                fake,
                logs,
                runtime,
            })
        }

        /// Waits until journalctl follows after its `runs`th run.
        async fn wait_for_follow(&self, runs: usize) {
            wait_for("journalctl follows", WAIT, || {
                self.fake.args().len() == runs
            })
            .await;
        }

        /// Every lost-interval warning logged.
        fn warnings(&self) -> Vec<String> {
            self.capture
                .text()
                .lines()
                .filter(|line| line.contains(GAP))
                .map(|line| {
                    assert!(line.contains("WARN"), "{line}");
                    let start = line.find("journal entries between").expect("the wording");
                    line[start..].to_string()
                })
                .collect()
        }

        /// How often the line about unavailable sequence numbers was logged.
        fn unavailable(&self) -> usize {
            let text = self.capture.text();
            for line in text.lines().filter(|line| line.contains(UNAVAILABLE)) {
                assert!(line.contains("INFO"), "{line}");
            }
            text.matches(UNAVAILABLE).count()
        }

        async fn shutdown(mut self) {
            self.runtime.shutdown().await;
        }
    }

    /// Starts the collector over `entries`, from `saved` (as in
    /// [`Run::start`]), and returns the lost-interval warnings and the
    /// number of lines about unavailable sequence numbers once the entry
    /// `last` is acknowledged.
    async fn check(
        saved: Option<(u64, Option<u64>)>,
        entries: &[Value],
        last: u64,
    ) -> Result<(Vec<String>, usize)> {
        let run = Run::start(saved, entries).await?;
        wait_for_cursor(&run.logs.state(), last).await;
        let checked = (run.warnings(), run.unavailable());
        run.shutdown().await;
        Ok(checked)
    }

    #[tokio::test]
    async fn a_clock_step_back_moves_to_a_new_stream_after_the_close_ack() -> Result<()> {
        let (logs_capture, _guard) = Logs::capture();
        let (_pki, giganto, files) = setup()?;
        let fake = Fake::new()?;
        // The clock stepped back before entry 3, in the batch of entries 1
        // to 4.
        fake.push(&[
            entry(1, KEPT),
            entry(2, KEPT),
            timed(3, time(1) - 1000),
            timed(4, time(1) - 999),
        ])?;
        let logs = LogFiles::new()?;
        let reload = ReloadSignal::new();
        let mut runtime = fake.runtime(&files.files, &reload, &logs.state());
        giganto.withhold(Withhold::Kinds(HashSet::from([JOURNAL.to_string()])));

        runtime.apply(journal_config(giganto.addr, &[])).await;
        wait_for("the first stream is closed", WAIT, || {
            giganto
                .streams_of(JOURNAL)
                .first()
                .is_some_and(|stream| stream.close_marker)
        })
        .await;
        wait_for("journalctl follows", WAIT, || fake.args().len() == 2).await;
        let follow = fake.last_pid();
        // More entries than the reader's channel and journalctl's pipe hold
        // wait behind the held one.
        let later = (5..=10_004)
            .map(|n| timed(n, time(1) + n))
            .collect::<Vec<_>>();
        fake.push(&later)?;
        sleep(SETTLE).await;
        let blocked = written(follow)?;
        sleep(SETTLE).await;
        assert_eq!(written(follow)?, blocked, "journalctl is held back");
        let total = length(&fake.path("entries"));
        assert!(blocked < total, "{blocked} of {total} bytes written");
        let streams = giganto.streams_of(JOURNAL);
        assert_eq!(streams.len(), 1, "the new stream waits for the close ACK");
        assert_eq!(streams[0].lines(), messages(1..=2));

        giganto.withhold(Withhold::Nothing);
        wait_for_count(&giganto, 10_004).await;
        let streams = giganto.streams_of(JOURNAL);
        assert_eq!(streams.len(), 2);
        assert_eq!(streams[0].lines(), messages(1..=2));
        assert_eq!(streams[0].timestamps, [stamp(time(1)), stamp(time(2))]);
        // The held entry opens the new stream with its own time, and the
        // entries behind it follow, each once.
        assert_eq!(streams[1].lines(), messages(3..=10_004));
        assert_eq!(
            streams[1].timestamps[..3],
            [
                stamp(time(1) - 1000),
                stamp(time(1) - 999),
                stamp(time(1) + 5)
            ]
        );
        assert!(streams[1].ended.is_none());
        assert_increasing_stamps(&giganto);
        assert_eq!(fake.args().len(), 2, "journalctl went on");
        assert!(running(follow));
        assert_eq!(
            logs_capture
                .text()
                .matches("the host clock stepped back")
                .count(),
            1
        );
        wait_for_cursor(&logs.state(), 10_004).await;

        runtime.shutdown().await;
        Ok(())
    }

    #[tokio::test]
    async fn a_drop_of_the_new_stream_sends_the_held_entry_again() -> Result<()> {
        let (_pki, giganto, files) = setup()?;
        let fake = Fake::new()?;
        fake.push(&[entry(1, KEPT), entry(2, KEPT)])?;
        let logs = LogFiles::new()?;
        let reload = ReloadSignal::new();
        let mut runtime = fake.runtime(&files.files, &reload, &logs.state());

        runtime.apply(journal_config(giganto.addr, &[])).await;
        wait_for_messages(&giganto, 1..=2).await;
        wait_for_cursor(&logs.state(), 2).await;
        wait_for("journalctl follows", WAIT, || fake.args().len() == 2).await;
        giganto.hold_acks(&[JOURNAL]).await;
        // The step back is the first record of its batch.
        fake.push(&[timed(3, time(1) - 1000), timed(4, time(1) - 999)])?;
        wait_for("the new stream carries the held entry", WAIT, || {
            giganto
                .streams_of(JOURNAL)
                .get(1)
                .is_some_and(|stream| stream.lines() == messages(3..=4))
        })
        .await;
        assert!(giganto.streams_of(JOURNAL)[0].close_marker);

        // The new stream drops before the held entry is acknowledged.
        giganto.stop_stream_of(JOURNAL)?;
        wait_for("a third stream carries the held entry again", WAIT, || {
            giganto
                .streams_of(JOURNAL)
                .get(2)
                .is_some_and(|stream| stream.lines() == messages(3..=4))
        })
        .await;
        assert_eq!(fake.args()[2], format!("--after-cursor={}", cursor(2)));
        giganto.release_acks().await;
        wait_for_cursor(&logs.state(), 4).await;
        // No entry of the old stream is sent again.
        assert_eq!(giganto.lines(JOURNAL), messages([1, 2, 3, 4, 3, 4]));
        assert_eq!(
            giganto.streams_of(JOURNAL)[2].timestamps,
            [stamp(time(1) - 1000), stamp(time(1) - 999)]
        );
        assert_increasing_stamps(&giganto);

        runtime.shutdown().await;
        Ok(())
    }

    #[tokio::test]
    async fn two_clock_steps_back_in_a_row_open_a_stream_each() -> Result<()> {
        let (_pki, giganto, files) = setup()?;
        let fake = Fake::new()?;
        let t = time(1);
        fake.push(&[
            timed(1, t),
            timed(2, t - 100),
            timed(3, t - 200),
            timed(4, t - 150),
        ])?;
        let logs = LogFiles::new()?;
        let reload = ReloadSignal::new();
        let mut runtime = fake.runtime(&files.files, &reload, &logs.state());

        runtime.apply(journal_config(giganto.addr, &[])).await;
        wait_for_messages(&giganto, 1..=4).await;
        wait_for_cursor(&logs.state(), 4).await;
        let streams = giganto.streams_of(JOURNAL);
        let carried = streams
            .iter()
            .map(|stream| {
                (
                    stream.lines(),
                    stream.timestamps.clone(),
                    stream.close_marker,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            carried,
            [
                (messages([1]), vec![stamp(t)], true),
                (messages([2]), vec![stamp(t - 100)], true),
                (
                    messages([3, 4]),
                    vec![stamp(t - 200), stamp(t - 150)],
                    false
                ),
            ]
        );
        assert_eq!(fake.args().len(), 2, "journalctl went on");

        runtime.shutdown().await;
        Ok(())
    }

    /// A step back without a close ACK: the collector rewinds to the last
    /// data acknowledgement, and compares the first entry the rewind reads
    /// with it.
    #[tokio::test]
    async fn a_missing_close_ack_rewinds_to_the_last_data_acknowledgement() -> Result<()> {
        let run = Run::start(None, &[entry(1, KEPT), entry(2, KEPT)]).await?;
        let (giganto, fake) = (&run.giganto, &run.fake);
        wait_for_messages(giganto, 1..=2).await;
        wait_for_cursor(&run.logs.state(), 2).await;
        run.wait_for_follow(2).await;
        giganto.hold_acks(&[JOURNAL]).await;
        giganto.withhold(Withhold::Kinds(HashSet::from([JOURNAL.to_string()])));
        fake.push(&[entry(3, KEPT)])?;
        wait_for_messages(giganto, [3]).await;
        let follow = fake.last_pid();
        fake.push(&[timed(4, time(1) - 1000), timed(5, time(1) - 999)])?;
        wait_for("the stream is closed", WAIT, || {
            giganto.streams_of(JOURNAL)[0].close_marker
        })
        .await;
        let closed = Instant::now();
        // Entry 3, never acknowledged, is removed meanwhile.
        fake.rewrite(&[
            entry(1, KEPT),
            entry(2, KEPT),
            timed(4, time(1) - 1000),
            timed(5, time(1) - 999),
        ])?;

        wait_for("a new stream opens", CLOSE_DEADLINE + WAIT, || {
            giganto.streams_of(JOURNAL).len() == 2
        })
        .await;
        let waited = closed.elapsed();
        assert!(
            waited + Duration::from_millis(500) >= CLOSE_DEADLINE,
            "{waited:?}"
        );
        giganto.withhold(Withhold::Nothing);
        giganto.release_acks().await;
        wait_for_messages(giganto, [4, 5]).await;
        assert!(!running(follow), "journalctl was stopped");
        assert_eq!(fake.args()[2], format!("--after-cursor={}", cursor(2)));
        let streams = giganto.streams_of(JOURNAL);
        assert_eq!(streams[0].lines(), messages(1..=3));
        assert_eq!(streams[1].lines(), messages([4, 5]));
        assert_eq!(
            streams[1].timestamps,
            [stamp(time(1) - 1000), stamp(time(1) - 999)]
        );
        assert_increasing_stamps(giganto);
        assert_eq!(
            run.warnings(),
            [gap(&named(2), "2023-11-14T22:13:19.999001Z")]
        );
        wait_for_cursor(&run.logs.state(), 5).await;

        run.shutdown().await;
        Ok(())
    }

    #[tokio::test]
    async fn entries_without_a_usable_time_neither_switch_nor_move_the_previous_time() -> Result<()>
    {
        let t = time(1);
        let run = Run::start(
            None,
            &[
                entry(1, KEPT),
                without(2, "__REALTIME_TIMESTAMP"),
                entry_with(
                    3,
                    &json!({ "_SYSTEMD_UNIT": KEPT, "__REALTIME_TIMESTAMP": "soon" }),
                ),
                // Its time in nanoseconds does not fit an i64.
                timed(4, u64::MAX / 1000),
                // The previous usable time is entry 1's.
                timed(5, t),
                timed(6, t + 1),
                timed(7, t - 1),
            ],
        )
        .await?;
        wait_for_cursor(&run.logs.state(), 7).await;
        let streams = run.giganto.streams_of(JOURNAL);
        assert_eq!(streams.len(), 2, "only entry 7 steps back");
        assert_eq!(streams[0].lines(), messages(1..=6));
        let first = stamp(t);
        assert_eq!(
            streams[0].timestamps,
            [
                first,
                first + 1,
                first + 2,
                first + 3,
                first + 4,
                stamp(t + 1)
            ]
        );
        assert_eq!(streams[1].timestamps, [stamp(t - 1)]);

        run.shutdown().await;
        Ok(())
    }

    #[tokio::test]
    async fn a_gap_after_the_saved_cursor_warns_once() -> Result<()> {
        let (warnings, unavailable) = check(
            Some((0, Some(0))),
            &[entry(0, KEPT), entry(3, KEPT), entry(4, KEPT)],
            4,
        )
        .await?;
        assert_eq!(
            warnings,
            ["journal entries between 2023-11-14T22:13:20.000000Z and \
              2023-11-14T22:13:20.000003Z may be missing: removed before they were sent, \
              or lost by journald"]
        );
        assert_eq!(unavailable, 0);
        Ok(())
    }

    #[tokio::test]
    async fn contiguous_and_filtered_entries_do_not_warn() -> Result<()> {
        // Contiguous.
        let checked = check(
            Some((2, Some(2))),
            &[
                entry(1, KEPT),
                entry(2, KEPT),
                entry(3, KEPT),
                entry(4, KEPT),
            ],
            4,
        )
        .await?;
        assert_eq!(checked, (vec![], 0));
        // The first entry read is dropped; the first one kept is later.
        let checked = check(
            Some((2, Some(2))),
            &[
                entry(1, KEPT),
                entry(2, KEPT),
                entry(3, DROPPED),
                entry(4, KEPT),
            ],
            4,
        )
        .await?;
        assert_eq!(checked, (vec![], 0));
        Ok(())
    }

    #[tokio::test]
    async fn over_long_lines_count_as_entries_read() -> Result<()> {
        // One skipped right after the cursor.
        let checked = check(
            Some((2, Some(2))),
            &[entry(1, KEPT), entry(2, KEPT), long(3), entry(4, KEPT)],
            4,
        )
        .await?;
        assert_eq!(checked, (vec![], 0));
        // Two skipped, and a real gap after them.
        let checked = check(
            Some((2, Some(2))),
            &[
                entry(1, KEPT),
                entry(2, KEPT),
                long(3),
                long(4),
                entry(7, KEPT),
            ],
            7,
        )
        .await?;
        assert_eq!(checked, (vec![gap(&named(2), &named(7))], 0));
        Ok(())
    }

    #[tokio::test]
    async fn a_new_sequence_number_id_warns_once() -> Result<()> {
        let other = "00000000000000000000000000000001";
        let checked = check(
            Some((2, Some(2))),
            &[
                entry(1, KEPT),
                entry(2, KEPT),
                entry_with(3, &json!({ "_SYSTEMD_UNIT": KEPT, "__SEQNUM_ID": other })),
                entry_with(4, &json!({ "_SYSTEMD_UNIT": KEPT, "__SEQNUM_ID": other })),
            ],
            4,
        )
        .await?;
        assert_eq!(checked, (vec![gap(&named(2), &named(3))], 0));
        Ok(())
    }

    #[tokio::test]
    async fn missing_sequence_numbers_skip_the_check_with_a_line_per_run() -> Result<()> {
        // On the first entry.
        let checked = check(
            Some((2, Some(2))),
            &[
                entry(1, KEPT),
                entry(2, KEPT),
                without(3, "__SEQNUM"),
                entry(9, KEPT),
            ],
            9,
        )
        .await?;
        assert_eq!(checked, (vec![], 1));
        // On the saved position.
        let checked = check(
            Some((2, None)),
            &[entry(1, KEPT), entry(2, KEPT), entry(5, KEPT)],
            5,
        )
        .await?;
        assert_eq!(checked, (vec![], 1));
        // Two runs of skipped comparisons, with a comparison made between.
        let checked = check(
            Some((2, Some(2))),
            &[
                entry(1, KEPT),
                entry(2, KEPT),
                without(3, "__SEQNUM"),
                without(4, "__SEQNUM_ID"),
                entry(5, KEPT),
                entry(6, KEPT),
                without(7, "__SEQNUM"),
            ],
            7,
        )
        .await?;
        assert_eq!(checked, (vec![], 2));
        Ok(())
    }

    #[tokio::test]
    async fn the_largest_sequence_number_does_not_overflow() -> Result<()> {
        let checked = check(
            Some((2, Some(u64::MAX))),
            &[
                entry(1, KEPT),
                entry(2, KEPT),
                entry_with(
                    3,
                    &json!({ "_SYSTEMD_UNIT": KEPT, "__SEQNUM": u64::MAX.to_string() }),
                ),
            ],
            3,
        )
        .await?;
        assert_eq!(checked, (vec![], 0));
        Ok(())
    }

    #[tokio::test]
    async fn the_first_entry_without_a_checkpoint_is_not_compared() -> Result<()> {
        let checked = check(None, &[entry(5, KEPT), entry(6, KEPT)], 6).await?;
        assert_eq!(checked, (vec![], 0));
        Ok(())
    }

    #[tokio::test]
    async fn times_unknown_to_the_warning_are_named_so() -> Result<()> {
        let checked = check(
            None,
            &[
                without(1, "__REALTIME_TIMESTAMP"),
                // Past what the warning's times represent.
                timed(3, 300_000_000_000_000_000),
                entry(5, KEPT),
            ],
            5,
        )
        .await?;
        assert_eq!(
            checked,
            (
                vec![
                    gap("an unknown time", "an unknown time"),
                    gap("an unknown time", &named(5)),
                ],
                0
            )
        );
        Ok(())
    }

    #[tokio::test]
    async fn the_start_position_is_compared_with_the_first_follow_entry() -> Result<()> {
        // Catch-up reads nothing after the saved cursor.
        let run = Run::start(Some((2, Some(2))), &[entry(1, KEPT), entry(2, KEPT)]).await?;
        run.wait_for_follow(2).await;
        run.fake.push(&[entry(5, KEPT)])?;
        wait_for_cursor(&run.logs.state(), 5).await;
        assert_eq!(run.warnings(), [gap(&named(2), &named(5))]);
        run.shutdown().await;
        Ok(())
    }

    #[tokio::test]
    async fn the_last_catch_up_entry_is_compared_with_the_first_follow_entry() -> Result<()> {
        let run = Run::start(None, &[entry(1, KEPT), entry(2, KEPT)]).await?;
        run.wait_for_follow(2).await;
        wait_for_cursor(&run.logs.state(), 2).await;
        run.fake.push(&[entry(4, KEPT)])?;
        wait_for_cursor(&run.logs.state(), 4).await;
        assert_eq!(run.warnings(), [gap(&named(2), &named(4))]);
        run.shutdown().await;
        Ok(())
    }

    #[tokio::test]
    async fn a_corrupt_checkpoints_tail_is_compared_with_the_first_follow_entry() -> Result<()> {
        let (capture, _guard) = Logs::capture();
        let (_pki, giganto, files) = setup()?;
        let fake = Fake::new()?;
        fake.push(&[entry(1, KEPT), entry(2, KEPT), entry(3, KEPT)])?;
        let logs = LogFiles::new()?;
        std::fs::create_dir(logs.state().join("checkpoints"))?;
        std::fs::write(journal_file(&logs.state()), b"garbage")?;
        let reload = ReloadSignal::new();
        let mut runtime = fake.runtime(&files.files, &reload, &logs.state());

        runtime.apply(journal_config(giganto.addr, &[])).await;
        wait_for("journalctl follows", WAIT, || fake.args().len() == 3).await;
        fake.push(&[entry(5, KEPT)])?;
        wait_for_messages(&giganto, [5]).await;
        let text = capture.text();
        assert_eq!(text.matches(GAP).count(), 1, "{text}");
        assert!(text.contains(&gap(&named(3), &named(5))), "{text}");

        runtime.shutdown().await;
        Ok(())
    }

    #[tokio::test]
    async fn a_gap_later_in_the_same_follow_process_warns_once() -> Result<()> {
        let run = Run::start(
            Some((2, Some(2))),
            &[entry(1, KEPT), entry(2, KEPT), entry(3, KEPT)],
        )
        .await?;
        run.wait_for_follow(2).await;
        wait_for_cursor(&run.logs.state(), 3).await;
        assert_eq!(run.warnings(), Vec::<String>::new());
        let follow = run.fake.last_pid();
        run.fake
            .push(&[entry(4, KEPT), entry(6, KEPT), entry(7, KEPT)])?;
        wait_for_cursor(&run.logs.state(), 7).await;
        assert_eq!(run.warnings(), [gap(&named(4), &named(6))]);
        assert_eq!(run.fake.args().len(), 2, "journalctl was not restarted");
        assert!(running(follow));
        run.shutdown().await;
        Ok(())
    }

    /// After a journalctl restart, the first entry is compared with the last
    /// one read before it, and an over-long line read again is counted once.
    #[tokio::test]
    async fn a_journalctl_restart_compares_with_the_last_entry_read() -> Result<()> {
        let run = Run::start(None, &[entry(1, KEPT), entry(2, KEPT)]).await?;
        run.wait_for_follow(2).await;
        run.fake.push(&[long(3)])?;
        wait_for("the over-long line is skipped", WAIT, || {
            run.capture.text().contains("skipped 1 journal entries")
        })
        .await;
        let status = std::process::Command::new("kill")
            .args(["-KILL", &run.fake.last_pid().to_string()])
            .status()?;
        assert!(status.success());
        wait_for("journalctl follows again", WAIT, || {
            run.fake.args().len() == 4
        })
        .await;
        assert_eq!(
            run.fake.args()[2..4],
            [
                format!("--after-cursor={}", cursor(2)),
                format!("--follow --lines=all --after-cursor={}", cursor(2)),
            ]
        );
        // Entry 4 is missing.
        run.fake.push(&[entry(5, KEPT)])?;
        wait_for_cursor(&run.logs.state(), 5).await;
        assert_eq!(run.warnings(), [gap(&named(2), &named(5))]);
        run.shutdown().await;
        Ok(())
    }

    #[tokio::test]
    async fn the_predecessor_is_kept_across_a_clock_step_switch() -> Result<()> {
        let run = Run::start(None, &[entry(1, KEPT), entry(2, KEPT)]).await?;
        run.wait_for_follow(2).await;
        wait_for_cursor(&run.logs.state(), 2).await;
        // Entry 4 is missing after the step back.
        run.fake
            .push(&[timed(3, time(1) - 1000), timed(5, time(1) - 999)])?;
        wait_for_cursor(&run.logs.state(), 5).await;
        assert_eq!(run.giganto.streams_of(JOURNAL).len(), 2);
        assert_eq!(
            run.warnings(),
            [gap(
                "2023-11-14T22:13:19.999001Z",
                "2023-11-14T22:13:19.999002Z"
            )]
        );
        run.shutdown().await;
        Ok(())
    }

    /// A gap at the rewind after a stream drop warns once, also when a
    /// second drop before any ACK replays it.
    #[tokio::test]
    async fn a_rewind_after_a_stream_drop_compares_its_start_position() -> Result<()> {
        let run = Run::start(None, &[entry(1, KEPT), entry(2, KEPT)]).await?;
        let (giganto, fake) = (&run.giganto, &run.fake);
        run.wait_for_follow(2).await;
        wait_for_cursor(&run.logs.state(), 2).await;
        giganto.hold_acks(&[JOURNAL]).await;
        // Entries 3 and 4 are removed while journalctl follows.
        fake.rewrite(&[entry(1, KEPT), entry(2, KEPT), entry(5, KEPT)])?;
        assert_eq!(run.warnings(), Vec::<String>::new());

        giganto.stop_stream_of(JOURNAL)?;
        wait_for("a new stream carries entry 5", WAIT, || {
            giganto
                .streams_of(JOURNAL)
                .get(1)
                .is_some_and(|stream| stream.lines() == messages([5]))
        })
        .await;
        assert_eq!(fake.args()[2], format!("--after-cursor={}", cursor(2)));
        assert_eq!(run.warnings(), [gap(&named(2), &named(5))]);

        // A second drop before any ACK reads the gap again.
        giganto.stop_stream_of(JOURNAL)?;
        wait_for("a third stream carries entry 5", WAIT, || {
            giganto
                .streams_of(JOURNAL)
                .get(2)
                .is_some_and(|stream| stream.lines() == messages([5]))
        })
        .await;
        assert_eq!(fake.args()[4], format!("--after-cursor={}", cursor(2)));
        giganto.release_acks().await;
        wait_for_cursor(&run.logs.state(), 5).await;
        assert_eq!(run.warnings(), [gap(&named(2), &named(5))]);
        run.shutdown().await;
        Ok(())
    }

    #[tokio::test]
    async fn a_gap_replayed_after_a_rewind_warns_once() -> Result<()> {
        let run = Run::start(None, &[entry(1, KEPT), entry(2, KEPT), entry(3, KEPT)]).await?;
        let (giganto, fake) = (&run.giganto, &run.fake);
        run.wait_for_follow(2).await;
        wait_for_cursor(&run.logs.state(), 3).await;
        giganto.hold_acks(&[JOURNAL]).await;
        fake.push(&[entry(4, KEPT), entry(7, KEPT)])?;
        wait_for_messages(giganto, [4, 7]).await;
        assert_eq!(run.warnings(), [gap(&named(4), &named(7))]);

        giganto.stop_stream_of(JOURNAL)?;
        wait_for("a new stream carries the entries again", WAIT, || {
            giganto
                .streams_of(JOURNAL)
                .get(1)
                .is_some_and(|stream| stream.lines() == messages([4, 7]))
        })
        .await;
        assert_eq!(fake.args()[2], format!("--after-cursor={}", cursor(3)));
        giganto.release_acks().await;
        wait_for_cursor(&run.logs.state(), 7).await;
        assert_eq!(run.warnings(), [gap(&named(4), &named(7))]);
        run.shutdown().await;
        Ok(())
    }
}
