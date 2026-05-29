//! Integration tests for tracing initialization defaults.

use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use tempfile::{TempDir, tempdir};

/// Emitted by `init_tracing` at INFO once stdout logging is configured.
const LOG_INIT_INFO_LOG: &str = "Initialized tracing logger";

fn fixture_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn write_minimal_config(temp_dir: &TempDir, input_dir: &Path) -> PathBuf {
    let cert = fixture_path("tests/cert.pem");
    let key = fixture_path("tests/key.pem");
    let root = fixture_path("tests/root.pem");
    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 38370);
    let config = format!(
        r#"cert = "{cert}"
key = "{key}"
ca_certs = ["{root}"]
giganto_ingest_srv_addr = "{addr}"
giganto_name = "localhost"
kind = "custom"
input = "{input}"
report = false

[directory]
polling_mode = true
"#,
        cert = cert.display(),
        key = key.display(),
        root = root.display(),
        addr = server_addr,
        input = input_dir.display(),
    );
    let config_path = temp_dir.path().join("config.toml");
    std::fs::write(&config_path, config).expect("write test config");
    config_path
}

/// Spawn `reproduce` with `RUST_LOG` unset and wait until an INFO startup
/// line appears on stdout.
#[test]
fn stdout_defaults_to_info_when_rust_log_unset() {
    let temp_dir = tempdir().expect("tempdir");
    let input_dir = temp_dir.path().join("input");
    std::fs::create_dir(&input_dir).expect("create input dir");
    let config_path = write_minimal_config(&temp_dir, &input_dir);

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
