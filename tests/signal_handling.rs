//! Process-level signal handling tests.
//!
//! These tests spawn the `reproduce` binary as a child process, establish a
//! minimal Giganto-compatible QUIC server, and verify that:
//!
//! - `SIGHUP` does NOT terminate the daemon (it requests a TLS reload).
//! - `SIGINT` and `SIGTERM` gracefully terminate the daemon.

#![cfg(unix)]

use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use giganto_client::connection::server_handshake;
use quinn::Endpoint;
use reproduce::sender::{CHANNEL_CLOSE_TIMESTAMP, REQUIRED_GIGANTO_VERSION};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tempfile::{TempDir, tempdir};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

const TEST_SERVER_NAME: &str = "localhost";
const CONNECT_SETTLE: Duration = Duration::from_secs(3);
const POST_SIGNAL_DWELL: Duration = Duration::from_secs(2);
const EXIT_WAIT: Duration = Duration::from_secs(30);

fn fixture_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn load_cert_chain(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let pem = std::fs::read(path).with_context(|| format!("read cert chain {}", path.display()))?;
    rustls_pemfile::certs(&mut &*pem)
        .collect::<std::result::Result<_, _>>()
        .context("parse cert chain PEM")
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let pem = std::fs::read(path).with_context(|| format!("read key {}", path.display()))?;
    rustls_pemfile::private_key(&mut &*pem)
        .context("parse private key PEM")?
        .context("private key PEM contained no key")
}

fn build_server_endpoint() -> Result<(Endpoint, SocketAddr)> {
    let cert_chain = load_cert_chain(&fixture_path("tests/cert.pem"))?;
    let private_key = load_private_key(&fixture_path("tests/key.pem"))?;

    let server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .context("test server TLS config")?;
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
            .context("test server QUIC config")?,
    ));
    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let endpoint = Endpoint::server(server_config, bind).context("bind test server")?;
    let addr = endpoint.local_addr().context("test server local addr")?;
    Ok((endpoint, addr))
}

/// Minimal Giganto-compatible test server. Accepts one client connection,
/// completes the protocol handshake, accepts the client's data stream, and
/// when any bytes arrive replies with the channel-close sentinel so the
/// client's `finish()` returns promptly during graceful shutdown.
fn spawn_test_server(endpoint: Endpoint) -> JoinHandle<()> {
    tokio::spawn(async move {
        let Ok(Some(incoming)) = timeout(Duration::from_secs(10), endpoint.accept()).await else {
            return;
        };
        let Ok(connection) = incoming.await else {
            return;
        };
        let _ = server_handshake(&connection, REQUIRED_GIGANTO_VERSION).await;

        let Ok(Ok((mut send_stream, mut recv_stream))) =
            timeout(Duration::from_secs(10), connection.accept_bi()).await
        else {
            let _ = connection.closed().await;
            return;
        };

        // As soon as the client writes any frame (it will be the CHANNEL_CLOSE
        // frame sent from `GigantoSender::finish()` during shutdown), reply
        // with the channel-close ACK so the client stops waiting.
        let mut buf = [0_u8; 64];
        if matches!(recv_stream.read(&mut buf).await, Ok(Some(_))) {
            let _ = send_stream
                .write_all(&CHANNEL_CLOSE_TIMESTAMP.to_be_bytes())
                .await;
            let _ = send_stream.finish();
        }

        let _ = connection.closed().await;
    })
}

fn write_config(temp_dir: &TempDir, server_addr: SocketAddr, input_dir: &Path) -> Result<PathBuf> {
    let cert = fixture_path("tests/cert.pem");
    let key = fixture_path("tests/key.pem");
    let root = fixture_path("tests/root.pem");
    let config = format!(
        r#"cert = "{cert}"
key = "{key}"
ca_certs = ["{root}"]
giganto_ingest_srv_addr = "{addr}"
giganto_name = "{name}"
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
        name = TEST_SERVER_NAME,
        input = input_dir.display(),
    );
    let config_path = temp_dir.path().join("config.toml");
    std::fs::write(&config_path, config).context("write test config")?;
    Ok(config_path)
}

fn send_signal(pid: u32, signal: libc::c_int) {
    // SAFETY: kill(2) with a valid PID and a defined signal number has no
    // safety invariants the caller can violate from Rust.
    let rc = unsafe { libc::kill(pid.cast_signed(), signal) };
    assert_eq!(rc, 0, "libc::kill({pid}, {signal}) failed: {rc}");
}

async fn wait_for_exit(child: &mut Child, within: Duration) -> Option<ExitStatus> {
    let start = Instant::now();
    while start.elapsed() < within {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) => sleep(Duration::from_millis(100)).await,
            Err(_) => return None,
        }
    }
    None
}

fn reap(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Spawn the binary and drain its stderr in the background so that pipe
/// back-pressure cannot stall the process.
fn spawn_reproduce(config_path: &Path) -> Result<Child> {
    let bin = env!("CARGO_BIN_EXE_reproduce");
    let mut child = Command::new(bin)
        .arg(config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawn reproduce binary")?;
    if let Some(stdout) = child.stdout.take() {
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                eprintln!("[reproduce stdout] {line}");
            }
        });
    }
    if let Some(stderr) = child.stderr.take() {
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                eprintln!("[reproduce stderr] {line}");
            }
        });
    }
    Ok(child)
}

async fn run_signal_scenario(termination_signal: libc::c_int) -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let (server_endpoint, server_addr) = build_server_endpoint()?;
    let server_task = spawn_test_server(server_endpoint);

    let temp_dir = tempdir().context("tempdir")?;
    let input_dir = temp_dir.path().join("input");
    std::fs::create_dir(&input_dir).context("create input dir")?;
    let config_path = write_config(&temp_dir, server_addr, &input_dir)?;

    let mut child = spawn_reproduce(&config_path)?;
    let pid = child.id();

    // Let the client connect and enter the directory-polling loop.
    sleep(CONNECT_SETTLE).await;
    if let Ok(Some(status)) = child.try_wait() {
        server_task.abort();
        anyhow::bail!("process exited before signals were delivered: {status:?}");
    }

    // SIGHUP must NOT terminate the process.
    send_signal(pid, libc::SIGHUP);
    sleep(POST_SIGNAL_DWELL).await;
    if let Ok(Some(status)) = child.try_wait() {
        server_task.abort();
        anyhow::bail!("process exited after SIGHUP: {status:?}");
    }

    // A termination signal must gracefully stop the process.
    send_signal(pid, termination_signal);
    let status = wait_for_exit(&mut child, EXIT_WAIT).await;

    server_task.abort();

    if status.is_some() {
        return Ok(());
    }
    reap(&mut child);
    anyhow::bail!(
        "process did not exit within {}s of termination signal {termination_signal}",
        EXIT_WAIT.as_secs()
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sighup_does_not_terminate_and_sigterm_does() {
    run_signal_scenario(libc::SIGTERM)
        .await
        .expect("SIGHUP should be reload-only; SIGTERM should terminate");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sighup_does_not_terminate_and_sigint_does() {
    run_signal_scenario(libc::SIGINT)
        .await
        .expect("SIGHUP should be reload-only; SIGINT should terminate");
}
