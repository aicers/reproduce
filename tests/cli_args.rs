//! Integration tests for CLI argument parsing.
//!
//! Tests verify exit codes and stdout/stderr output for:
//! - No arguments
//! - Too many arguments
//! - Help flag (-h, --help)
//! - Version flag (-V, --version)

use assert_cmd::Command;
use predicates::prelude::*;

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
        .stdout(predicate::str::contains(PKG_VERSION));
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
        .stderr(predicate::str::contains("insufficient arguments"));
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
        .stderr(predicate::str::contains("too many arguments"));
}
