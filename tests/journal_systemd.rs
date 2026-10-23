//! The journal collector under systemd, against the host's own journal.
//!
//! The binary runs in remote mode as the transient unit
//! `clumit-security-reproduce-test.service`, as a non-root system user,
//! against the in-process Giganto ([`support::giganto`]) and the mock
//! Central Manager ([`support::Mock`]) on `127.0.0.1`. Journal entries come
//! from transient units `clumit-security-journaltest-<token>-<n>.service`
//! that print lines, `<token>` naming one run of a test.
//!
//! The tests are ignored: they need `sudo` without a password, systemd, a
//! persistent journal, and a system user that is not in group `adm`, named
//! by `JOURNAL_TEST_USER` (by default `clumit-security-reproduce-test`). CI's
//! `journal-systemd` job runs them with
//! `cargo test --test journal_systemd -- --ignored --test-threads=1
//! --show-output`; they share the unit name, so they run one at a time, and
//! the back-pressure test prints what it observed. Each removes its
//! transient units and files when it ends, also on failure.
#![cfg(target_os = "linux")]

mod support;

use std::collections::HashSet;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Output;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use giganto_client::ingest::log::{OpLog, OpLogLevel};
use serde_json::Value;
use support::giganto::{Giganto, JOURNAL};
use support::{Files, Mock, Pki, SERVER_NAME};
use tempfile::TempDir;
use tokio::process::Command;
use tokio::time::{Instant, sleep};

/// The unit the binary runs as.
const UNIT: &str = "clumit-security-reproduce-test.service";
/// The `service_name` of the binary's own entries.
const SERVICE: &str = "clumit-security/unit/clumit-security-reproduce-test.service";
/// Names the system user the unit runs as.
const USER_VAR: &str = "JOURNAL_TEST_USER";
const DEFAULT_USER: &str = "clumit-security-reproduce-test";
/// How long a test waits for something that should happen.
const WAIT: Duration = Duration::from_secs(120);
/// How long a test waits to show that something does not happen.
const SETTLE: Duration = Duration::from_secs(3);
/// What ends the lost-interval warning.
const GAP: &str = "may be missing: removed before they were sent, or lost by journald";
/// What the binary logs when it cannot read the system journal.
const ACCESS_ERROR: &str = "cannot read the system journal; is the unit in group adm?";

/// Runs `program` with `args`, and returns its output if it succeeds.
async fn run(program: &str, args: &[&str]) -> Result<Output> {
    let output = Command::new(program)
        .args(args)
        .output()
        .await
        .with_context(|| format!("{program} runs"))?;
    ensure!(
        output.status.success(),
        "{program} {args:?}: {}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(output)
}

async fn sudo(args: &[&str]) -> Result<Output> {
    let mut all = vec!["-n"];
    all.extend_from_slice(args);
    run("sudo", &all).await
}

/// Runs `sudo journalctl --output=json` with `args`, returning the entries.
async fn journal(args: &[&str]) -> Result<Vec<Value>> {
    let mut all = vec!["journalctl", "--output=json", "--all", "--no-pager"];
    all.extend_from_slice(args);
    let output = sudo(&all).await?;
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| serde_json::from_str(line).context("a JSON entry"))
        .collect()
}

/// A field of a journal entry as text; journalctl writes a field that is
/// not printable text as an array of bytes.
fn field(entry: &Value, name: &str) -> Option<Vec<u8>> {
    match entry.get(name)? {
        Value::String(s) => Some(s.as_bytes().to_vec()),
        Value::Array(bytes) => bytes
            .iter()
            .map(|byte| byte.as_u64().and_then(|byte| u8::try_from(byte).ok()))
            .collect(),
        _ => None,
    }
}

fn text(entry: &Value, name: &str) -> Option<String> {
    field(entry, name).map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
}

/// Waits until `condition` returns `true`, at most `within`.
async fn wait_for<F, Fut>(what: &str, within: Duration, mut condition: F) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<bool>>,
{
    let deadline = Instant::now() + within;
    loop {
        if condition().await? {
            return Ok(());
        }
        ensure!(Instant::now() < deadline, "timed out waiting until {what}");
        sleep(Duration::from_millis(200)).await;
    }
}

/// One record a journal stream received.
#[derive(Clone, Debug)]
struct Received {
    /// The index of its stream at the server.
    stream: usize,
    stamp: i64,
    op_log: OpLog,
}

/// The binary as a unit, the servers it talks to, and the files it uses.
struct Host {
    _pki: Pki,
    giganto: Giganto,
    mock: Mock,
    /// Holds the binary, the TLS files, the state directory and the `log`
    /// collector's file; readable by the unit's user.
    dir: TempDir,
    user: String,
    /// Names the test units of this run.
    token: String,
    units: AtomicUsize,
}

impl Host {
    async fn new() -> Result<Self> {
        let user = std::env::var(USER_VAR).unwrap_or_else(|_| DEFAULT_USER.to_string());
        let groups = run("id", &["-nG", &user]).await?;
        ensure!(
            !String::from_utf8_lossy(&groups.stdout)
                .split_whitespace()
                .any(|group| group == "adm"),
            "{user} must not be in group adm"
        );
        let pki = Pki::new()?;
        let giganto = Giganto::start(&pki)?;
        let mock = Mock::start(&pki)?;
        let dir = tempfile::Builder::new()
            .prefix("clumit-security-reproduce-test-")
            .tempdir()?;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755))?;
        let binary = dir.path().join("reproduce");
        std::fs::copy(env!("CARGO_BIN_EXE_reproduce"), &binary)?;
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755))?;
        let files = Files::new(&pki, &pki.client()?)?;
        for (from, name) in [
            (&files.files.cert, "cert.pem"),
            (&files.files.key, "key.pem"),
            (&files.files.ca_certs[0], "ca.pem"),
        ] {
            let to = dir.path().join(name);
            std::fs::copy(from, &to)?;
            std::fs::set_permissions(&to, std::fs::Permissions::from_mode(0o644))?;
        }
        let log = dir.path().join("journaltest.log");
        std::fs::write(&log, "log line 1\nlog line 2\n")?;
        std::fs::set_permissions(&log, std::fs::Permissions::from_mode(0o644))?;
        let state = dir.path().join("state");
        let state_dir = state.to_str().context("a UTF-8 path")?;
        sudo(&["install", "-d", "-o", &user, "-m", "0700", state_dir]).await?;
        mock.set_config(Some(&format!(
            r#"
giganto_ingest_srv_addr = "{}"
giganto_name = "{SERVER_NAME}"

[[collectors]]
type = "journal"

[[collectors]]
type = "log"
kind = "journaltest"
path = "{}"
start = "beginning"
"#,
            giganto.addr,
            log.display()
        )));
        // Lowercase hexadecimal, so that test units match
        // `clumit-security-*.service`.
        let token = format!("{:x}{:x}", std::process::id(), epoch_seconds());
        Ok(Self {
            _pki: pki,
            giganto,
            mock,
            dir,
            user,
            token,
            units: AtomicUsize::new(0),
        })
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// Starts the binary as the unit, with `SupplementaryGroups=adm` if
    /// `adm`.
    async fn start(&self, adm: bool) -> Result<()> {
        let path = |name: &str| self.path(name).to_string_lossy().into_owned();
        let user = format!("User={}", self.user);
        let manager = format!("{SERVER_NAME}@{}", self.mock.addr);
        let (binary, cert, key, ca, state) = (
            path("reproduce"),
            path("cert.pem"),
            path("key.pem"),
            path("ca.pem"),
            path("state"),
        );
        let mut args = vec![
            "systemd-run",
            "--quiet",
            "--collect",
            "--unit",
            UNIT,
            "-p",
            &user,
        ];
        if adm {
            args.extend(["-p", "SupplementaryGroups=adm"]);
        }
        args.extend([
            "--",
            &binary,
            "--cert",
            &cert,
            "--key",
            &key,
            "--ca-certs",
            &ca,
            "--state-dir",
            &state,
            &manager,
        ]);
        sudo(&args).await?;
        Ok(())
    }

    /// Stops the unit, as a clean stop does.
    async fn stop(&self) -> Result<()> {
        sudo(&["systemctl", "stop", UNIT]).await?;
        Ok(())
    }

    /// Kills the unit with SIGKILL and waits until it is gone.
    async fn kill(&self) -> Result<()> {
        sudo(&["systemctl", "kill", "--signal=SIGKILL", UNIT]).await?;
        wait_for("the unit is gone", WAIT, || async {
            Ok(!self.active().await)
        })
        .await?;
        let _ = sudo(&["systemctl", "reset-failed", UNIT]).await;
        Ok(())
    }

    async fn active(&self) -> bool {
        sudo(&["systemctl", "is-active", "--quiet", UNIT])
            .await
            .is_ok()
    }

    async fn property(&self, name: &str) -> Result<String> {
        let output = sudo(&["systemctl", "show", "--value", "-p", name, UNIT]).await?;
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    /// The journalctl processes the unit runs.
    async fn journalctls(&self) -> Result<Vec<String>> {
        let cgroup = self.property("ControlGroup").await?;
        let procs = std::fs::read_to_string(format!("/sys/fs/cgroup{cgroup}/cgroup.procs"))?;
        let mut pids = Vec::new();
        for pid in procs.split_whitespace() {
            let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
            if comm.trim() == "journalctl" {
                pids.push(pid.to_string());
            }
        }
        Ok(pids)
    }

    /// The unit's own entries of its current invocation.
    async fn own_entries(&self, invocation: &str) -> Result<Vec<Value>> {
        Ok(journal(&["-u", UNIT])
            .await?
            .into_iter()
            .filter(|entry| {
                text(entry, "_SYSTEMD_UNIT").as_deref() == Some(UNIT)
                    && text(entry, "_SYSTEMD_INVOCATION_ID").as_deref() == Some(invocation)
            })
            .collect())
    }

    /// The name of the next test unit.
    fn next_unit(&self) -> String {
        let n = self.units.fetch_add(1, Ordering::SeqCst);
        format!("clumit-security-journaltest-{}-{n}.service", self.token)
    }

    /// Runs a test unit that prints `lines`, and waits until journald holds
    /// every line. Returns the unit's name.
    async fn write(&self, lines: &[String]) -> Result<String> {
        let unit = self.next_unit();
        let mut args = vec![
            "systemd-run",
            "--quiet",
            "--collect",
            "--wait",
            "--unit",
            &unit,
            "--",
            "/bin/sh",
            "-c",
            r#"printf '%s\n' "$@""#,
            "sh",
        ];
        args.extend(lines.iter().map(String::as_str));
        sudo(&args).await?;
        self.wait_for_entries(&unit, lines.len()).await?;
        Ok(unit)
    }

    /// Runs a test unit that prints `count` lines of about 1000 bytes,
    /// `<prefix>-<i> xxx…`, and waits until journald holds them.
    async fn write_many(&self, prefix: &str, count: usize) -> Result<String> {
        let unit = self.next_unit();
        let script = format!(
            r#"BEGIN {{ pad = sprintf("%1000s", ""); gsub(/ /, "x", pad); for (i = 0; i < {count}; i++) printf "%s-%d %s\n", "{prefix}", i, pad }}"#
        );
        sudo(&[
            "systemd-run",
            "--quiet",
            "--collect",
            "--wait",
            "--unit",
            &unit,
            "--",
            "/usr/bin/awk",
            &script,
        ])
        .await?;
        self.wait_for_entries(&unit, count).await?;
        Ok(unit)
    }

    async fn wait_for_entries(&self, unit: &str, count: usize) -> Result<()> {
        wait_for(
            &format!("journald holds {count} lines of {unit}"),
            WAIT,
            || async { Ok(self.entries(unit).await?.len() >= count) },
        )
        .await
    }

    /// The entries a test unit printed, in journal order.
    async fn entries(&self, unit: &str) -> Result<Vec<Value>> {
        Ok(journal(&["-u", unit])
            .await?
            .into_iter()
            .filter(|entry| text(entry, "_SYSTEMD_UNIT").as_deref() == Some(unit))
            .collect())
    }

    /// Every record the journal streams received, in order.
    fn received(&self) -> Vec<Received> {
        let mut received = Vec::new();
        for (index, stream) in self.giganto.streams().into_iter().enumerate() {
            if stream.kind() != Some(JOURNAL) {
                continue;
            }
            for (op_log, stamp) in stream.op_logs.into_iter().zip(stream.timestamps) {
                received.push(Received {
                    stream: index,
                    stamp,
                    op_log,
                });
            }
        }
        received
    }

    /// The contents received from this run's test units, in order.
    fn received_lines(&self) -> Vec<String> {
        let prefix = format!(
            "clumit-security/unit/clumit-security-journaltest-{}-",
            self.token
        );
        self.received()
            .into_iter()
            .filter(|record| record.op_log.service_name.starts_with(&prefix))
            .map(|record| record.op_log.contents)
            .collect()
    }

    async fn wait_for_lines(&self, lines: &[String]) -> Result<()> {
        wait_for(&format!("{} lines arrive", lines.len()), WAIT, || async {
            let received = self.received_lines().into_iter().collect::<HashSet<_>>();
            Ok(lines.iter().all(|line| received.contains(line)))
        })
        .await
    }

    /// Writes a marker line and waits until it arrives, so that every entry
    /// before it was read.
    async fn settle(&self, name: &str) -> Result<()> {
        let marker = format!("{name}-{}", self.token);
        self.write(std::slice::from_ref(&marker)).await?;
        self.wait_for_lines(&[marker]).await
    }

    /// The lost-interval warnings received on streams from `stream` on.
    fn warnings(&self, stream: usize) -> Vec<Received> {
        self.received()
            .into_iter()
            .filter(|record| record.stream >= stream && is_warning(record))
            .collect()
    }

    /// The lost-interval warnings received after the line `marker`.
    fn warnings_after(&self, marker: &str) -> Vec<Received> {
        self.received()
            .into_iter()
            .skip_while(|record| record.op_log.contents != marker)
            .filter(is_warning)
            .collect()
    }

    /// Stops journalctl from following, writes entries, rotates the
    /// journal, writes more, rotates it again and vacuums every archived
    /// file, so that the entries after the last one read are removed.
    async fn remove_unread_entries(&self) -> Result<()> {
        let lines = (0..3)
            .map(|n| format!("<6>removed-{}-{n}", self.token))
            .collect::<Vec<_>>();
        self.write(&lines).await?;
        sudo(&["journalctl", "--rotate"]).await?;
        self.write(&lines).await?;
        sudo(&["journalctl", "--rotate"]).await?;
        sudo(&["journalctl", "--vacuum-files=1"]).await?;
        Ok(())
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        let sudo = |args: &[&str]| {
            let _ = std::process::Command::new("sudo")
                .arg("-n")
                .args(args)
                .output();
        };
        sudo(&["systemctl", "stop", UNIT]);
        sudo(&["systemctl", "reset-failed", UNIT]);
        for n in 0..self.units.load(Ordering::SeqCst) {
            let unit = format!("clumit-security-journaltest-{}-{n}.service", self.token);
            sudo(&["systemctl", "stop", &unit]);
            sudo(&["systemctl", "reset-failed", &unit]);
        }
        // The state directory belongs to the unit's user.
        if let Some(state) = self.path("state").to_str() {
            sudo(&["rm", "-rf", "--", state]);
        }
    }
}

/// Tells whether a record is the binary's lost-interval warning.
fn is_warning(record: &Received) -> bool {
    record.op_log.service_name == SERVICE && record.op_log.contents.contains(GAP)
}

/// Seconds since the epoch, to tell the runs of the tests apart.
fn epoch_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// Writes entries outside any clumit-security unit, from this process: a
/// `logger` line, and one with a forged container name.
async fn forge(token: &str) -> Result<()> {
    use tokio::io::AsyncWriteExt;

    run("logger", &[&format!("forged-{token}-logger")]).await?;
    let mut logger = Command::new("logger")
        .arg("--journald")
        .stdin(std::process::Stdio::piped())
        .spawn()?;
    let mut stdin = logger.stdin.take().context("piped stdin")?;
    stdin
        .write_all(
            format!("MESSAGE=forged-{token}-container\nCONTAINER_NAME=clumit-security-forged\n")
                .as_bytes(),
        )
        .await?;
    drop(stdin);
    ensure!(logger.wait().await?.success(), "logger --journald");
    Ok(())
}

/// Asserts that the binary's own entries carry the priority of their level
/// and hold no escape, and that there is an INFO one.
fn assert_own_priorities(own: &[Value]) -> Result<()> {
    let mut info = 0;
    for entry in own {
        let message = field(entry, "MESSAGE").context("a message")?;
        assert!(!message.contains(&0x1b), "{entry}");
        let message = String::from_utf8_lossy(&message);
        let priority = text(entry, "PRIORITY");
        if message.trim_start().starts_with("INFO") {
            assert_eq!(priority.as_deref(), Some("6"), "{entry}");
            info += 1;
        } else if message.trim_start().starts_with("WARN") {
            assert_eq!(priority.as_deref(), Some("4"), "{entry}");
        }
    }
    assert!(info > 0, "{own:?}");
    Ok(())
}

/// Asserts the wording of a lost-interval warning: two RFC 3339 UTC times
/// with microseconds.
fn assert_wording(contents: &str) {
    let start = contents
        .find("journal entries between ")
        .unwrap_or_else(|| panic!("the wording: {contents}"));
    let rest = &contents[start + "journal entries between ".len()..];
    let (a, rest) = rest.split_once(" and ").expect("two times");
    let b = rest
        .strip_suffix(&format!(" {GAP}"))
        .unwrap_or_else(|| panic!("the wording: {contents}"));
    for time in [a, b] {
        let bytes = time.as_bytes();
        assert_eq!(bytes.len(), 27, "{time}");
        assert_eq!(bytes[19], b'.', "{time}");
        assert_eq!(bytes[26], b'Z', "{time}");
        assert!(bytes[20..26].iter().all(u8::is_ascii_digit), "{time}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs systemd, sudo and a persistent journal; run by CI's journal-systemd job"]
async fn a_unit_outside_group_adm_cannot_read_the_journal() -> Result<()> {
    let host = Host::new().await?;
    host.start(false).await?;
    let invocation = host.property("InvocationID").await?;
    wait_for("the access error is logged", WAIT, || async {
        Ok(host
            .own_entries(&invocation)
            .await?
            .iter()
            .any(|entry| text(entry, "MESSAGE").is_some_and(|m| m.contains(ACCESS_ERROR))))
    })
    .await?;
    sleep(SETTLE).await;
    assert!(
        host.giganto.streams_of(JOURNAL).is_empty(),
        "no journal stream opens"
    );
    host.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs systemd, sudo and a persistent journal; run by CI's journal-systemd job"]
async fn the_unit_sends_the_journal_from_its_oldest_entry_and_resumes_after_a_kill() -> Result<()> {
    let host = Host::new().await?;
    let token = host.token.clone();
    // Lines written before the start, at three priorities.
    let before = [
        format!("<3>error-{token}"),
        format!("<4>warning-{token}"),
        format!("<6>info-{token}"),
    ];
    let first = host.write(&before).await?;
    let second = host
        .write(&[format!("second-{token}-1"), format!("second-{token}-2")])
        .await?;
    forge(&token).await?;

    host.start(true).await?;
    let invocation = host.property("InvocationID").await?;
    let mut expected = vec![
        format!("error-{token}"),
        format!("warning-{token}"),
        format!("info-{token}"),
        format!("second-{token}-1"),
        format!("second-{token}-2"),
    ];
    host.wait_for_lines(&expected).await?;
    assert_eq!(host.received_lines(), expected, "in order, each once");
    // Service names, levels and stamps.
    let records = host.received();
    for (unit, levels) in [
        (
            &first,
            vec![OpLogLevel::Error, OpLogLevel::Warn, OpLogLevel::Info],
        ),
        (&second, vec![OpLogLevel::Info, OpLogLevel::Info]),
    ] {
        let service = format!("clumit-security/unit/{unit}");
        let entries = host.entries(unit).await?;
        let of_unit = records
            .iter()
            .filter(|record| record.op_log.service_name == service)
            .collect::<Vec<_>>();
        assert_eq!(of_unit.len(), entries.len(), "{unit}");
        for ((record, entry), level) in of_unit.iter().zip(&entries).zip(levels) {
            assert_eq!(
                Some(&record.op_log.contents),
                text(entry, "MESSAGE").as_ref()
            );
            assert_eq!(record.op_log.log_level, level, "{record:?}");
            let realtime = text(entry, "__REALTIME_TIMESTAMP")
                .context("a time")?
                .parse::<i64>()?;
            assert_eq!(record.stamp / 1000, realtime, "{record:?}");
        }
    }
    let forged = format!("forged-{token}");
    assert!(
        records
            .iter()
            .all(|record| !record.op_log.contents.contains(&forged)),
        "forged entries are not sent"
    );
    // The log collector's records share the connection.
    wait_for("the log collector's lines arrive", WAIT, || async {
        Ok(host.giganto.lines("journaltest") == ["log line 1", "log line 2"])
    })
    .await?;
    let connections = host
        .giganto
        .streams()
        .iter()
        .map(|stream| stream.connection)
        .collect::<HashSet<_>>();
    assert_eq!(connections.len(), 1, "one connection");

    // New lines while following, and a line of 10,000 bytes.
    let long = format!(
        "long-{token}-{}",
        "y".repeat(10_000 - "long--".len() - token.len())
    );
    assert_eq!(long.len(), 10_000);
    let follow = [format!("<6>follow-{token}"), long.clone()];
    host.write(&follow).await?;
    expected.extend([format!("follow-{token}"), long.clone()]);
    host.wait_for_lines(&expected).await?;
    assert_eq!(host.received_lines(), expected);

    assert_own_priorities(&host.own_entries(&invocation).await?)?;

    // Killed, and started again with the same state directory: the lines
    // written meanwhile arrive, and none is missing.
    host.kill().await?;
    let down = [format!("down-{token}-1"), format!("down-{token}-2")];
    host.write(&down).await?;
    host.start(true).await?;
    expected.extend(down);
    host.wait_for_lines(&expected).await?;
    let received = host.received_lines();
    for line in &expected {
        assert!(received.contains(line), "{line} arrives");
    }

    host.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs systemd, sudo and a persistent journal; run by CI's journal-systemd job"]
async fn a_vacuum_past_the_saved_cursor_warns_once() -> Result<()> {
    let host = Host::new().await?;
    host.start(true).await?;
    host.settle("started").await?;
    host.stop().await?;

    host.remove_unread_entries().await?;
    let streams = host.giganto.streams().len();
    host.start(true).await?;
    let invocation = host.property("InvocationID").await?;
    wait_for("the lost-interval warning arrives", WAIT, || async {
        Ok(!host.warnings(streams).is_empty())
    })
    .await?;
    host.settle("after").await?;
    let warnings = host.warnings(streams);
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert_eq!(warnings[0].op_log.log_level, OpLogLevel::Warn);
    assert_wording(&warnings[0].op_log.contents);
    // The unit's own entry is a warning.
    let own = host.own_entries(&invocation).await?;
    let gaps = own
        .iter()
        .filter(|entry| text(entry, "MESSAGE").is_some_and(|m| m.contains(GAP)))
        .collect::<Vec<_>>();
    assert_eq!(gaps.len(), 1, "{gaps:?}");
    assert_eq!(text(gaps[0], "PRIORITY").as_deref(), Some("4"));

    host.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs systemd, sudo and a persistent journal; run by CI's journal-systemd job"]
async fn a_vacuum_during_a_giganto_outage_warns_once_at_the_reconnect() -> Result<()> {
    let mut host = Host::new().await?;
    host.start(true).await?;
    host.settle("started").await?;

    host.giganto.stop().await;
    host.remove_unread_entries().await?;
    let streams = host.giganto.streams().len();
    host.giganto.restart().await?;
    wait_for("the lost-interval warning arrives", WAIT, || async {
        Ok(!host.warnings(streams).is_empty())
    })
    .await?;
    host.settle("after").await?;
    let warnings = host.warnings(streams);
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert_eq!(warnings[0].op_log.log_level, OpLogLevel::Warn);
    assert_wording(&warnings[0].op_log.contents);

    host.stop().await?;
    Ok(())
}

/// The server stops reading the journal stream, so that the collector and
/// journalctl are held back, while a rotation and a vacuum remove entries
/// journalctl has not read yet; then it reads again. The unit, journalctl
/// and the stream stay alive throughout.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs systemd, sudo and a persistent journal; run by CI's journal-systemd job"]
async fn a_vacuum_behind_back_pressure_is_reported_when_reading_resumes() -> Result<()> {
    // Under journald's default rate limit of 10,000 entries per unit in
    // 30 s.
    const PER_UNIT: usize = 8000;

    let host = Host::new().await?;
    let token = host.token.clone();
    host.start(true).await?;
    host.settle("started").await?;
    let streams = host.giganto.streams_of(JOURNAL).len();
    let main_pid = host.property("MainPID").await?;
    let journalctls = host.journalctls().await?;
    assert_eq!(journalctls.len(), 1, "journalctl follows");

    let pause = format!("pause-{token}");
    host.giganto.pause_reading_after(JOURNAL, &pause);
    host.write(std::slice::from_ref(&pause)).await?;
    host.wait_for_lines(std::slice::from_ref(&pause)).await?;
    // More than the stream's flow-control window, the reader's channel and
    // journalctl's pipe hold.
    let first = format!("bulk-{token}-a");
    let second = format!("bulk-{token}-b");
    host.write_many(&first, PER_UNIT).await?;
    sudo(&["journalctl", "--rotate"]).await?;
    host.write_many(&second, PER_UNIT).await?;
    sudo(&["journalctl", "--rotate"]).await?;
    sudo(&["journalctl", "--vacuum-files=1"]).await?;
    let bulk = format!("bulk-{token}-");
    let held = host
        .received_lines()
        .iter()
        .filter(|line| line.starts_with(&bulk))
        .count();
    host.giganto.resume_reading();
    host.settle("resumed").await?;
    // The first entry after the gap can be the marker itself, which the
    // warning then follows; a second marker follows the warning.
    host.settle("settled").await?;

    assert_eq!(host.property("MainPID").await?, main_pid, "the unit runs");
    assert_eq!(host.journalctls().await?, journalctls, "journalctl runs");
    let journal = host.giganto.streams_of(JOURNAL);
    assert_eq!(journal.len(), streams, "the stream is kept");
    assert!(journal.last().is_some_and(|stream| stream.ended.is_none()));
    let received = host.received_lines().into_iter().collect::<HashSet<_>>();
    let pad = "x".repeat(1000);
    let written = [&first, &second]
        .iter()
        .flat_map(|prefix| {
            let pad = &pad;
            (0..PER_UNIT).map(move |i| format!("{prefix}-{i} {pad}"))
        })
        .collect::<Vec<_>>();
    let missing = written
        .iter()
        .filter(|line| !received.contains(*line))
        .count();
    let warnings = host.warnings_after(&pause).len();
    eprintln!(
        "back pressure: {held} test lines received while held back; {missing} of {} entries \
         missing; {warnings} lost-interval warnings",
        written.len()
    );
    if missing > 0 {
        assert!(warnings >= 1, "{missing} entries missing without a warning");
    }

    host.stop().await?;
    Ok(())
}
