//! Process-level signal handling tests.
//!
//! These tests spawn the `reproduce` binary as a child process, establish a
//! minimal Giganto-compatible QUIC server, and verify that:
//!
//! - `SIGHUP` does NOT terminate the daemon (it requests a TLS reload).
//! - `SIGINT` and `SIGTERM` gracefully terminate the daemon.
//! - After `SIGHUP`, a forced reconnect actually uses the rotated TLS
//!   material (the reload effect is observable, not just "process survived").

#![cfg(unix)]

use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use giganto_client::connection::server_handshake;
use quinn::{Connection, Endpoint};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use reproduce::sender::{CHANNEL_CLOSE_TIMESTAMP, REQUIRED_GIGANTO_VERSION};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tempfile::{TempDir, tempdir};
use tokio::sync::oneshot;
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

/// Self-signed CA + server-leaf PEM material used to prove that a `SIGHUP`
/// reload is observable in real TLS behavior on the next reconnect.
struct ServerPki {
    ca: String,
    leaf_cert: String,
    leaf_key: String,
}

fn generate_server_pki(server_name: &str) -> Result<ServerPki> {
    let mut ca_params =
        CertificateParams::new(Vec::<String>::new()).context("ca params should be valid")?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Reload Test CA");
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_key = KeyPair::generate().context("ca key should generate")?;
    let ca_cert = ca_params
        .self_signed(&ca_key)
        .context("ca should self-sign")?;
    let ca_issuer =
        Issuer::from_ca_cert_der(ca_cert.der(), &ca_key).context("ca issuer should build")?;

    let mut leaf_params = CertificateParams::new(vec![server_name.to_string()])
        .context("server leaf params should be valid")?;
    leaf_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, server_name);
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf_key = KeyPair::generate().context("server leaf key should generate")?;
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &ca_issuer)
        .context("server leaf should be signed by CA")?;

    Ok(ServerPki {
        ca: ca_cert.pem(),
        leaf_cert: leaf_cert.pem(),
        leaf_key: leaf_key.serialize_pem(),
    })
}

fn build_rotating_server_config(pki: &ServerPki) -> Result<quinn::ServerConfig> {
    let cert_bytes = pki.leaf_cert.as_bytes();
    let cert_chain: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut &*cert_bytes)
        .collect::<std::result::Result<_, _>>()
        .context("server cert PEM should parse")?;
    let key_bytes = pki.leaf_key.as_bytes();
    let private_key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut &*key_bytes)
        .context("server key PEM should parse")?
        .context("server key PEM contained no key")?;
    let server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .context("server TLS config should build")?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
            .context("QUIC server config should build")?,
    )))
}

fn build_rotating_endpoint(pki: &ServerPki) -> Result<(Endpoint, SocketAddr)> {
    let server_config = build_rotating_server_config(pki)?;
    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let endpoint = Endpoint::server(server_config, bind).context("bind rotating test server")?;
    let addr = endpoint
        .local_addr()
        .context("rotating server local addr")?;
    Ok((endpoint, addr))
}

fn write_reload_config(
    temp_dir: &TempDir,
    server_addr: SocketAddr,
    input_dir: &Path,
    ca_path: &Path,
) -> Result<PathBuf> {
    let cert = fixture_path("tests/cert.pem");
    let key = fixture_path("tests/key.pem");
    let config = format!(
        r#"cert = "{cert}"
key = "{key}"
ca_certs = ["{ca}"]
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
        ca = ca_path.display(),
        addr = server_addr,
        name = TEST_SERVER_NAME,
        input = input_dir.display(),
    );
    let config_path = temp_dir.path().join("reload-config.toml");
    std::fs::write(&config_path, config).context("write reload config")?;
    Ok(config_path)
}

/// Accepts one incoming QUIC connection that completes both the TLS and the
/// Giganto application handshake. Connections that fail the TLS handshake
/// (e.g., a client still presenting stale CA material) are discarded and
/// the next one is attempted, so this helper only returns once a client
/// that trusts the currently configured server identity has connected.
async fn accept_one_verified(endpoint: Endpoint) -> Result<Connection> {
    loop {
        let incoming = endpoint
            .accept()
            .await
            .ok_or_else(|| anyhow!("endpoint closed before accepting a connection"))?;
        let Ok(conn) = incoming.await else {
            continue;
        };
        if server_handshake(&conn, REQUIRED_GIGANTO_VERSION)
            .await
            .is_ok()
        {
            return Ok(conn);
        }
    }
}

/// Replaces `target` atomically with `new_contents` so concurrent readers
/// never observe a torn file mid-rotation.
fn rotate_file(target: &Path, new_contents: &str) -> Result<()> {
    let tmp = target.with_extension("pem.rotating");
    std::fs::write(&tmp, new_contents).context("write rotation staging file")?;
    std::fs::rename(&tmp, target).context("atomic rename during rotation")?;
    Ok(())
}

/// End-to-end proof that `SIGHUP` creates reload intent and that intent is
/// observable at the next reconnect boundary: a second QUIC handshake that
/// can only succeed when the client has actually read the rotated CA file
/// from disk.
///
/// Scenario:
/// 1. Start a QUIC server using PKI v1. Launch `reproduce` with v1 CA on disk.
/// 2. Wait for the initial handshake to succeed.
/// 3. Rotate the CA file on disk to PKI v2 and send `SIGHUP`.
/// 4. Swap the running endpoint's server config to PKI v2 and close the v1
///    connection to force the client to reconnect.
/// 5. Drop an input file so the client tries to send; the broken stream
///    returns `WriteError`, triggering `reconnect()` which rebuilds the
///    endpoint with the rotated CA material.
/// 6. Assert that a **second** TLS handshake completes. If `SIGHUP` were
///    silently ignored, the client would still trust only PKI v1 and the
///    reconnect to the now-v2 server would fail certificate verification.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sighup_reload_uses_rotated_tls_on_next_reconnect() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let pki_v1 = generate_server_pki(TEST_SERVER_NAME).expect("PKI v1 should generate");
    let pki_v2 = generate_server_pki(TEST_SERVER_NAME).expect("PKI v2 should generate");

    let (endpoint, server_addr) =
        build_rotating_endpoint(&pki_v1).expect("rotating endpoint should bind");

    let (conn_v1_tx, conn_v1_rx) = oneshot::channel();
    let (conn_v2_tx, conn_v2_rx) = oneshot::channel();

    let server_endpoint = endpoint.clone();
    let server_task: JoinHandle<Result<()>> = tokio::spawn(async move {
        let conn_v1 = accept_one_verified(server_endpoint.clone()).await?;
        let _ = conn_v1_tx.send(conn_v1);
        let conn_v2 = accept_one_verified(server_endpoint).await?;
        let _ = conn_v2_tx.send(conn_v2);
        Ok(())
    });

    let temp_dir = tempdir()
        .context("tempdir")
        .expect("tempdir should be created");
    let input_dir = temp_dir.path().join("input");
    std::fs::create_dir(&input_dir).expect("create input dir");
    let ca_path = temp_dir.path().join("ca.pem");
    std::fs::write(&ca_path, &pki_v1.ca).expect("seed CA file with v1 material");
    let config_path = write_reload_config(&temp_dir, server_addr, &input_dir, &ca_path)
        .expect("write reload config");

    let mut child = spawn_reproduce(&config_path).expect("spawn reproduce binary");
    let pid = child.id();

    let conn_v1 = match timeout(Duration::from_secs(20), conn_v1_rx).await {
        Ok(Ok(conn)) => conn,
        other => {
            server_task.abort();
            reap(&mut child);
            panic!("initial (v1) handshake did not complete: {other:?}");
        }
    };

    // Rotate CA file on disk to PKI v2 BEFORE signalling, so the reload
    // handler picks up the new material the moment it fires.
    if let Err(error) = rotate_file(&ca_path, &pki_v2.ca) {
        server_task.abort();
        reap(&mut child);
        panic!("failed to rotate CA file: {error}");
    }

    // Ask the daemon to reload — this is the behaviour under test.
    send_signal(pid, libc::SIGHUP);

    // New incoming QUIC connections will now be served with PKI v2.
    let v2_server_config =
        build_rotating_server_config(&pki_v2).expect("v2 server config should build");
    endpoint.set_server_config(Some(v2_server_config));

    // Force the client out of its current session so its next send will
    // observe a `WriteError` and invoke `reconnect()`.
    conn_v1.close(0u32.into(), b"server rotating");
    drop(conn_v1);

    // Give the client something to send so the pipeline attempts a write
    // on the (now broken) v1 stream and then reconnects.
    std::fs::write(input_dir.join("payload.log"), b"reload-probe\n")
        .expect("write probe input file");

    let reload_succeeded = timeout(Duration::from_secs(90), conn_v2_rx).await.is_ok();

    if !reload_succeeded {
        server_task.abort();
        send_signal(pid, libc::SIGTERM);
        let _ = wait_for_exit(&mut child, EXIT_WAIT).await;
        reap(&mut child);
        panic!(
            "reconnect after SIGHUP did not complete a TLS handshake with rotated CA; \
             either SIGHUP was ignored or the reload path did not pick up the new CA file"
        );
    }

    send_signal(pid, libc::SIGTERM);
    let _ = wait_for_exit(&mut child, EXIT_WAIT).await;
    reap(&mut child);

    server_task.abort();
    drop(endpoint);
}
