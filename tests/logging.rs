//! Integration tests for tracing initialization defaults.

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use tempfile::tempdir;

/// Emitted by `init_tracing` at INFO once stdout logging is configured.
const LOG_INIT_INFO_LOG: &str = "Initialized tracing logger";

fn write_tracing_startup_config() -> (tempfile::TempDir, PathBuf) {
    let temp_dir = tempdir().expect("tempdir");
    let config = r#"cert = "unused-cert.pem"
key = "unused-key.pem"
ca_certs = ["unused-root.pem"]
giganto_ingest_srv_addr = "127.0.0.1:1"
giganto_name = "localhost"
kind = "custom"
input = "unused.log"
report = false
"#;
    let config_path = temp_dir.path().join("config.toml");
    std::fs::write(&config_path, config).expect("write test config");
    (temp_dir, config_path)
}

/// Spawn `reproduce` with `RUST_LOG` unset and wait until an INFO startup
/// line appears on stdout.
#[test]
fn stdout_defaults_to_info_when_rust_log_unset() {
    let (_temp_dir, config_path) = write_tracing_startup_config();

    let bin = env!("CARGO_BIN_EXE_reproduce");
    let mut child = Command::new(bin)
        .arg(&config_path)
        .env_remove("RUST_LOG")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn reproduce binary");

    let stdout = child.stdout.take().expect("stdout pipe");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let found = BufReader::new(stdout)
            .lines()
            .map_while(Result::ok)
            .any(|line| line.contains(LOG_INIT_INFO_LOG));
        let _ = tx.send(found);
    });

    let saw_info = rx.recv_timeout(Duration::from_secs(10)).unwrap_or(false);

    let _ = child.kill();
    let _ = child.wait();

    assert!(
        saw_info,
        "stdout logging should emit INFO by default when RUST_LOG is unset"
    );
}
