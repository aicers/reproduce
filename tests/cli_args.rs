//! Integration tests for CLI argument parsing.
//!
//! Tests verify exit codes and stdout/stderr output for:
//! - No arguments
//! - Too many arguments
//! - Help flag (-h, --help)
//! - Version flag (-V, --version)
//! - Local and remote invocation forms and their refusals

use assert_cmd::Command;
use predicates::prelude::*;

/// The first line of the remote-mode form in the usage text.
const REMOTE_FORM: &str = "reproduce --cert <CERT_PATH> --key <KEY_PATH> --ca-certs <CA_PATHS> \
                           --state-dir <DIR> <MANAGER>";

/// The local-mode form in the usage text.
const LOCAL_FORM: &str = "reproduce <CONFIG>";

/// Returns the package version from Cargo.toml at compile time.
const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Helper function to create a `Command` for the binary under test.
fn reproduce_cmd() -> Command {
    let mut command = assert_cmd::cargo::cargo_bin_cmd!();
    command.env_remove("JOURNAL_STREAM");
    command
}

/// Tests that running with `-h` flag prints help information and exits
/// successfully.
#[test]
fn help_short_flag() {
    reproduce_cmd()
        .arg("-h")
        .assert()
        .success()
        .stdout(predicate::str::contains("USAGE"))
        .stdout(predicate::str::contains(PKG_VERSION))
        .stdout(predicate::str::contains(LOCAL_FORM))
        .stdout(predicate::str::contains(REMOTE_FORM));
}

/// Tests that running with `--help` flag prints help information and exits
/// successfully.
#[test]
fn help_long_flag() {
    reproduce_cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("USAGE"))
        .stdout(predicate::str::contains(PKG_VERSION));
}

/// Tests that running with `-V` flag prints version information and exits
/// successfully.
#[test]
fn version_short_flag() {
    reproduce_cmd()
        .arg("-V")
        .assert()
        .success()
        .stdout(predicate::str::contains(PKG_VERSION));
}

/// Tests that running with `--version` flag prints version information and
/// exits successfully.
#[test]
fn version_long_flag() {
    reproduce_cmd()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(PKG_VERSION));
}

/// Tests that running without arguments fails with exit code 1 and prints an
/// error message to stderr.
#[test]
fn no_arguments() {
    reproduce_cmd()
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("Error: insufficient arguments"))
        .stderr(predicate::str::contains(LOCAL_FORM))
        .stderr(predicate::str::contains(REMOTE_FORM));
}

/// Tests that running with too many arguments fails with exit code 1 and prints
/// an error message to stderr.
#[test]
fn too_many_arguments() {
    reproduce_cmd()
        .args(["one", "two", "three"])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("Error: too many arguments"))
        .stderr(predicate::str::contains(LOCAL_FORM))
        .stderr(predicate::str::contains(REMOTE_FORM));
}

/// Returns a remote-mode invocation with the given state directory and
/// manager endpoint.
fn remote_args<'a>(state_dir: &'a str, manager: &'a str) -> [&'a str; 9] {
    [
        "--cert",
        "tests/cert.pem",
        "--key",
        "tests/key.pem",
        "--ca-certs",
        "tests/root.pem",
        "--state-dir",
        state_dir,
        manager,
    ]
}

/// Asserts that an invocation is refused with exit code 1, the given reason
/// and both forms on stderr.
fn assert_refused(args: &[&str], reason: &str) {
    reproduce_cmd()
        .args(args)
        .assert()
        .failure()
        .code(1)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::starts_with("Error: "))
        .stderr(predicate::str::contains(reason))
        .stderr(predicate::str::contains(LOCAL_FORM))
        .stderr(predicate::str::contains(REMOTE_FORM));
}

/// Tests that the local form still reads the configuration file: a missing
/// file is reported as it was before remote mode existed.
#[test]
fn local_form_reads_the_configuration() {
    let temp_dir = tempfile::tempdir().expect("temporary directory");
    let config = temp_dir.path().join("missing.toml");
    reproduce_cmd()
        .arg(&config)
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("Error:"))
        .stderr(predicate::str::contains("USAGE").not());
}

/// Tests that a local configuration path starting with `-` is taken as a flag.
#[test]
fn local_path_starting_with_dash_is_a_flag() {
    assert_refused(&["-name.toml"], "unknown flag -name.toml");
}

/// A remote-mode process whose standard output is read line by line.
#[cfg(unix)]
struct RemoteProcess {
    child: std::process::Child,
    lines: std::sync::mpsc::Receiver<String>,
    stdout: String,
}

#[cfg(unix)]
impl RemoteProcess {
    fn spawn(args: &[&str]) -> Self {
        use std::io::BufRead;

        let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_reproduce"))
            .args(args)
            .env_remove("RUST_LOG")
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("reproduce starts");
        let stdout = child.stdout.take().expect("piped stdout");
        let (sender, lines) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(stdout)
                .lines()
                .map_while(Result::ok)
            {
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            lines,
            stdout: String::new(),
        }
    }

    /// Waits until a line of standard output contains `text`.
    fn wait_for(&mut self, text: &str) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while !self.stdout.contains(text) {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            let Ok(line) = self.lines.recv_timeout(remaining) else {
                let _ = self.child.kill();
                panic!("no line containing {text:?}; output:\n{}", self.stdout);
            };
            self.stdout.push_str(&line);
            self.stdout.push('\n');
        }
    }

    /// Sends `SIGTERM` and asserts that the process exits 0.
    fn terminate(mut self) -> String {
        let pid = libc::pid_t::try_from(self.child.id()).expect("a valid pid");
        // SAFETY: `kill` has no memory-safety preconditions.
        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let status = loop {
            if let Some(status) = self.child.try_wait().expect("waitable child") {
                break status;
            }
            if std::time::Instant::now() > deadline {
                let _ = self.child.kill();
                panic!("no exit after SIGTERM; output:\n{}", self.stdout);
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        };
        while let Ok(line) = self.lines.recv_timeout(std::time::Duration::from_secs(5)) {
            self.stdout.push_str(&line);
            self.stdout.push('\n');
        }
        assert_eq!(status.code(), Some(0), "output:\n{}", self.stdout);
        self.stdout
    }
}

/// Tests that the remote form keeps running against an unreachable manager,
/// after creating the state directory, and exits 0 on `SIGTERM` while its
/// first connect attempt is still in progress.
#[cfg(unix)]
#[test]
fn remote_form_runs_against_an_unreachable_manager() {
    let temp_dir = tempfile::tempdir().expect("temporary directory");
    let state_dir = temp_dir.path().join("state");
    let state_dir = state_dir.to_str().expect("UTF-8 path");
    let mut process = RemoteProcess::spawn(&remote_args(state_dir, "manager@127.0.0.1:38390"));
    process.wait_for("Remote mode: manager manager@127.0.0.1:38390");
    process.wait_for("Connecting to the Central Manager at 127.0.0.1:38390");
    std::thread::sleep(std::time::Duration::from_secs(1));
    assert!(
        process.child.try_wait().expect("waitable child").is_none(),
        "the process keeps running"
    );
    assert!(std::path::Path::new(state_dir).is_dir());
    let stdout = process.terminate();
    // A connect to a silent port fails only at the idle timeout.
    assert!(!stdout.contains("Cannot connect"), "{stdout}");
    assert!(!stdout.contains("not available"), "{stdout}");
}

/// Tests that a refused connect is logged and retried, and that `SIGTERM`
/// ends the process with status 0.
#[cfg(unix)]
#[test]
fn remote_form_retries_a_refused_connect() {
    let temp_dir = tempfile::tempdir().expect("temporary directory");
    let state_dir = temp_dir.path().join("state");
    let state_dir = state_dir.to_str().expect("UTF-8 path");
    let mut process = RemoteProcess::spawn(&remote_args(state_dir, "manager@127.0.0.1:0"));
    process.wait_for("Cannot connect to the Central Manager at 127.0.0.1:0");
    assert!(process.stdout.contains("WARN"), "{}", process.stdout);
    process.terminate();
}

/// Tests that the remote form accepts an IPv6 manager endpoint.
#[cfg(unix)]
#[test]
fn remote_form_accepts_ipv6_manager() {
    let temp_dir = tempfile::tempdir().expect("temporary directory");
    let state_dir = temp_dir.path().join("state");
    let state_dir = state_dir.to_str().expect("UTF-8 path");
    let mut process = RemoteProcess::spawn(&remote_args(state_dir, "manager@[::1]:38390"));
    process.wait_for("Remote mode: manager manager@[::1]:38390");
    process.wait_for("Connecting to the Central Manager at [::1]:38390");
    process.terminate();
}

/// Tests that a missing certificate file stops startup with an error naming
/// it.
#[test]
fn remote_form_refuses_a_missing_certificate() {
    let temp_dir = tempfile::tempdir().expect("temporary directory");
    let state_dir = temp_dir.path().join("state");
    let state_dir = state_dir.to_str().expect("UTF-8 path");
    let mut args = remote_args(state_dir, "manager@127.0.0.1:38390");
    args[1] = "tests/missing-cert.pem";
    reproduce_cmd()
        .args(args)
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::starts_with("Error: "))
        .stderr(predicate::str::contains("tests/missing-cert.pem"));
}

/// Tests that a state directory under a regular file stops startup with an
/// error on stderr.
#[test]
fn remote_form_refuses_state_dir_under_a_file() {
    let temp_dir = tempfile::tempdir().expect("temporary directory");
    let file = temp_dir.path().join("file");
    std::fs::write(&file, "").expect("file is written");
    let state_dir = file.join("state");
    let state_dir = state_dir.to_str().expect("UTF-8 path");
    reproduce_cmd()
        .args(remote_args(state_dir, "manager@127.0.0.1:38390"))
        .assert()
        .failure()
        .code(1)
        .stdout(predicate::str::contains("not available").not())
        .stderr(predicate::str::contains("Error:"))
        .stderr(predicate::str::contains("state directory"));
}

/// Tests that a configuration path mixed with flags is refused.
#[test]
fn mixed_form_is_refused() {
    assert_refused(
        &["--cert", "tests/cert.pem", "tests/config.toml"],
        "cannot be combined with flags",
    );
    assert_refused(
        &remote_args("state", "tests/config.toml"),
        "not a manager endpoint",
    );
}

/// Tests the remote-form refusals.
#[test]
fn remote_form_refusals() {
    let valid = remote_args("state", "manager@127.0.0.1:38390");

    assert_refused(&valid[2..], "missing flag --cert");
    assert_refused(&valid[..8], "missing the manager endpoint");
    assert_refused(&[&valid[..], &["--key", "other.pem"]].concat(), "repeated");
    assert_refused(&[&valid[..], &["-h"]].concat(), "unknown flag -h");
    assert_refused(
        &[&valid[..], &["--version"]].concat(),
        "unknown flag --version",
    );
    assert_refused(
        &[&["--cert=tests/cert.pem"], &valid[2..]].concat(),
        "unknown flag",
    );
    assert_refused(&[&valid[..8], &["--cert"]].concat(), "repeated");
    assert_refused(&[&valid[2..], &["--cert"]].concat(), "missing its value");

    let mut empty_value = valid;
    empty_value[1] = "";
    assert_refused(&empty_value, "empty value");

    let mut empty_ca = valid;
    empty_ca[5] = "tests/root.pem,";
    assert_refused(&empty_ca, "invalid --ca-certs list");

    assert_refused(
        &remote_args("state", "manager@localhost:38390"),
        "not a manager endpoint",
    );
    assert_refused(
        &remote_args("state", "@127.0.0.1:38390"),
        "not a manager endpoint",
    );
}
