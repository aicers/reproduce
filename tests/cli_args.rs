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
    assert_cmd::cargo::cargo_bin_cmd!()
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

/// Tests that the remote form runs until the not-available line, after
/// creating the state directory.
#[test]
fn remote_form_reports_not_available() {
    let temp_dir = tempfile::tempdir().expect("temporary directory");
    let state_dir = temp_dir.path().join("state");
    let state_dir = state_dir.to_str().expect("UTF-8 path");
    reproduce_cmd()
        .args(remote_args(state_dir, "manager@127.0.0.1:38390"))
        .env_remove("RUST_LOG")
        .assert()
        .failure()
        .code(1)
        .stdout(predicate::str::contains(
            "Remote mode is not available in this build",
        ));
    assert!(std::path::Path::new(state_dir).is_dir());
}

/// Tests that the remote form accepts an IPv6 manager endpoint.
#[test]
fn remote_form_accepts_ipv6_manager() {
    let temp_dir = tempfile::tempdir().expect("temporary directory");
    let state_dir = temp_dir.path().join("state");
    let state_dir = state_dir.to_str().expect("UTF-8 path");
    reproduce_cmd()
        .args(remote_args(state_dir, "manager@[::1]:38390"))
        .env_remove("RUST_LOG")
        .assert()
        .failure()
        .code(1)
        .stdout(predicate::str::contains("manager@[::1]:38390"))
        .stdout(predicate::str::contains(
            "Remote mode is not available in this build",
        ));
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
