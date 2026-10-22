//! Test servers and fixtures shared by the sender tests.

use std::{
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result};
use giganto_client::{connection::server_handshake, frame::recv_raw};
use quinn::{Connection, Endpoint, RecvStream, SendStream};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::time::{Duration, timeout};
use tokio_util::sync::CancellationToken;

use super::{
    CHANNEL_CLOSE_TIMESTAMP, ConnectionConfig, GigantoConnection, REQUIRED_GIGANTO_VERSION,
    StreamErrorPolicy,
};
use crate::reload::ReloadSignal;

pub(super) const TEST_ROOT_PEM: &str = "tests/root.pem";
pub(super) const TEST_CERT_PEM: &str = "tests/cert.pem";
pub(super) const TEST_KEY_PEM: &str = "tests/key.pem";
pub(super) const TEST_SERVER_NAME: &str = "localhost";
pub(super) const TEST_TIMEOUT: Duration = Duration::from_secs(5);
/// Covers the reconnect delay plus a connect.
pub(super) const RECONNECT_TIMEOUT: Duration = Duration::from_secs(8);

pub(super) fn fixture_path(relative: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(relative)
        .to_string_lossy()
        .into_owned()
}

pub(super) fn load_cert_chain(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let cert_pem = fs::read(path).with_context(|| {
        format!(
            "test fixture certificate should be readable: {}",
            path.display()
        )
    })?;
    rustls_pemfile::certs(&mut &*cert_pem)
        .collect::<std::result::Result<_, _>>()
        .context("test fixture certificate PEM should be valid")
}

pub(super) fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let key_pem = fs::read(path).with_context(|| {
        format!(
            "test fixture private key should be readable: {}",
            path.display()
        )
    })?;
    rustls_pemfile::private_key(&mut &*key_pem)
        .context("test fixture private key PEM should be valid")?
        .context("test fixture private key PEM should contain a private key")
}

pub(super) fn build_server_endpoint() -> Result<(Endpoint, SocketAddr)> {
    let cert_chain = load_cert_chain(Path::new(&fixture_path(TEST_CERT_PEM)))?;
    let private_key = load_private_key(Path::new(&fixture_path(TEST_KEY_PEM)))?;

    let server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .context("test server certificate configuration should be valid")?;
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
            .context("test server QUIC config should build")?,
    ));
    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let endpoint =
        Endpoint::server(server_config, bind_addr).context("test server endpoint should bind")?;
    let addr = endpoint
        .local_addr()
        .context("test server endpoint should have a local address")?;
    Ok((endpoint, addr))
}

/// Returns a connection config for the fixture identity and `server_addr`.
pub(super) fn fixture_config(server_addr: SocketAddr) -> ConnectionConfig {
    ConnectionConfig {
        cert: fixture_path(TEST_CERT_PEM),
        key: fixture_path(TEST_KEY_PEM),
        ca_certs: vec![fixture_path(TEST_ROOT_PEM)],
        server_addr,
        server_name: TEST_SERVER_NAME.to_string(),
    }
}

/// Copies the fixture identity into `dir`, so a test can break it on disk.
pub(super) fn copied_fixture_config(dir: &Path, server_addr: SocketAddr) -> ConnectionConfig {
    let copy = |relative: &str, name: &str| {
        let target = dir.join(name);
        fs::copy(fixture_path(relative), &target).expect("fixture should be copied");
        target.to_string_lossy().into_owned()
    };
    ConnectionConfig {
        cert: copy(TEST_CERT_PEM, "cert.pem"),
        key: copy(TEST_KEY_PEM, "key.pem"),
        ca_certs: vec![copy(TEST_ROOT_PEM, "root.pem")],
        server_addr,
        server_name: TEST_SERVER_NAME.to_string(),
    }
}

/// Accepts one connection and completes the Giganto handshake.
pub(super) async fn accept_connection(
    server_endpoint: &Endpoint,
    within: Duration,
) -> Result<Connection> {
    let incoming = timeout(within, server_endpoint.accept())
        .await
        .context("test server should accept a connection in time")?
        .context("test server endpoint should stay open while accepting")?;
    let connection = incoming
        .await
        .context("client connection should complete QUIC setup")?;
    server_handshake(&connection, REQUIRED_GIGANTO_VERSION)
        .await
        .context("server handshake should succeed")?;
    Ok(connection)
}

pub(super) async fn accept_server_stream(
    connection: &Connection,
) -> Result<(SendStream, RecvStream)> {
    timeout(TEST_TIMEOUT, connection.accept_bi())
        .await
        .context("test server should accept the sender data stream in time")?
        .context("server should accept the sender data stream")
}

pub(super) struct ServerSession {
    pub(super) server_endpoint: Endpoint,
    pub(super) connection: Connection,
}

/// Connects a [`GigantoConnection`] to a fresh in-process test server.
pub(super) async fn connect_test_connection(
    policy: StreamErrorPolicy,
    reload: &ReloadSignal,
    token: CancellationToken,
) -> Result<(GigantoConnection, ServerSession)> {
    let (server_endpoint, server_addr) = build_server_endpoint()?;
    let (connection, server_conn) = tokio::join!(
        GigantoConnection::connect(fixture_config(server_addr), policy, reload, token),
        accept_connection(&server_endpoint, TEST_TIMEOUT),
    );
    Ok((
        connection.context("connection should be established")?,
        ServerSession {
            server_endpoint,
            connection: server_conn?,
        },
    ))
}

/// Reads one framed batch from a server-side stream.
pub(super) async fn recv_batch(recv: &mut RecvStream) -> Result<Vec<(i64, Vec<u8>)>> {
    let mut buf = Vec::new();
    timeout(TEST_TIMEOUT, recv_raw(recv, &mut buf))
        .await
        .context("server should receive a batch in time")?
        .context("server should receive a framed batch")?;
    bincode::deserialize(&buf).context("batch should deserialize")
}

/// Returns whether `batch` is the channel-close marker.
pub(super) fn is_close_marker(batch: &[(i64, Vec<u8>)]) -> bool {
    batch.len() == 1
        && batch
            .first()
            .is_some_and(|(ts, _)| *ts == CHANNEL_CLOSE_TIMESTAMP)
}
