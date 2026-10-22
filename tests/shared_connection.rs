//! Two streams sharing one Giganto connection.
//!
//! An in-process QUIC server, using the test certificates, receives two
//! concurrent streams on one connection. One stream is then reset while the
//! other keeps sending, and the other is later closed with its close marker
//! and close ACK, without a second connection ever being made.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use giganto_client::{
    RawEventKind, connection::server_handshake, frame::recv_raw, ingest::receive_record_header,
};
use quinn::{Connection, Endpoint, ReadError, RecvStream, SendStream};
use reproduce::reload::ReloadSignal;
use reproduce::sender::{
    AckDelivery, CHANNEL_CLOSE_TIMESTAMP, CloseAck, ConnectionConfig, GigantoConnection,
    REQUIRED_GIGANTO_VERSION, StreamErrorPolicy,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

const TEST_SERVER_NAME: &str = "localhost";
const TEST_TIMEOUT: Duration = Duration::from_secs(5);

fn fixture_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn fixture_string(relative: &str) -> String {
    fixture_path(relative).to_string_lossy().into_owned()
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

async fn accept_connection(endpoint: &Endpoint) -> Result<Connection> {
    let incoming = timeout(TEST_TIMEOUT, endpoint.accept())
        .await
        .context("server should accept a connection in time")?
        .context("server endpoint should stay open")?;
    let connection = incoming.await.context("QUIC setup should complete")?;
    server_handshake(&connection, REQUIRED_GIGANTO_VERSION)
        .await
        .context("server handshake should succeed")?;
    Ok(connection)
}

/// Accepts the next stream and reads its record header.
async fn accept_stream(connection: &Connection) -> Result<(u32, SendStream, RecvStream)> {
    let (send, mut recv) = timeout(TEST_TIMEOUT, connection.accept_bi())
        .await
        .context("server should accept a stream in time")?
        .context("server should accept a stream")?;
    let mut header = [0_u8; 4];
    receive_record_header(&mut recv, &mut header)
        .await
        .context("server should receive the record header")?;
    Ok((u32::from_le_bytes(header), send, recv))
}

async fn recv_batch(recv: &mut RecvStream) -> Result<Vec<(i64, Vec<u8>)>> {
    let mut buf = Vec::new();
    timeout(TEST_TIMEOUT, recv_raw(recv, &mut buf))
        .await
        .context("server should receive a batch in time")?
        .context("server should receive a framed batch")?;
    bincode::deserialize(&buf).context("batch should deserialize")
}

async fn ack(send: &mut SendStream, timestamp: i64) -> Result<()> {
    send.write_all(&timestamp.to_be_bytes())
        .await
        .context("server should send the ACK")
}

/// Returns whether `client` connects to `server_endpoint` within `within`.
///
/// Only connections from `client` count: the test server's port may be one
/// another client, in this process or another, still retries against.
async fn connects_from(server_endpoint: &Endpoint, client: SocketAddr, within: Duration) -> bool {
    timeout(within, async {
        while let Some(incoming) = server_endpoint.accept().await {
            if incoming.remote_address() == client {
                return;
            }
            incoming.ignore();
        }
        std::future::pending::<()>().await;
    })
    .await
    .is_ok()
}

/// Connects a connection owner to the test server.
async fn connect(
    server_endpoint: &Endpoint,
    server_addr: SocketAddr,
) -> Result<(GigantoConnection, Connection)> {
    let reload = ReloadSignal::new();
    let config = ConnectionConfig {
        cert: fixture_string("tests/cert.pem"),
        key: fixture_string("tests/key.pem"),
        ca_certs: vec![fixture_string("tests/root.pem")],
        server_addr,
        server_name: TEST_SERVER_NAME.to_string(),
    };
    let (connection, server_conn) = tokio::join!(
        GigantoConnection::connect(
            config,
            StreamErrorPolicy::ReopenStream,
            &reload,
            CancellationToken::new(),
        ),
        accept_connection(server_endpoint),
    );
    Ok((connection.context("client should connect")?, server_conn?))
}

#[tokio::test]
async fn two_streams_share_one_connection_through_reset_and_close() -> Result<()> {
    let (server_endpoint, server_addr) = build_server_endpoint()?;
    let (connection, server_conn) = connect(&server_endpoint, server_addr).await?;

    let (mut reset_stream, _) = connection
        .open_stream(CancellationToken::new(), AckDelivery::LogOnly)
        .await
        .context("first stream should open")?;
    let (mut kept_stream, kept_acks) = connection
        .open_stream(CancellationToken::new(), AckDelivery::Deliver)
        .await
        .context("second stream should open")?;
    let mut kept_acks = kept_acks.context("a delivering stream has an ACK receiver")?;

    // Both streams send their header and a batch concurrently.
    let reset_batch = [(1_i64, b"to-be-reset".to_vec())];
    let kept_batch = [(2_i64, b"kept".to_vec())];
    let (reset_result, kept_result) = tokio::join!(
        async {
            reset_stream.send_header(RawEventKind::Dns).await?;
            reset_stream
                .send_batch(&reset_batch)
                .await
                .map_err(reproduce::sender::SenderError::Send)
        },
        async {
            kept_stream.send_header(RawEventKind::Log).await?;
            kept_stream
                .send_batch(&kept_batch)
                .await
                .map_err(reproduce::sender::SenderError::Send)
        },
    );
    reset_result.context("first stream should send")?;
    kept_result.context("second stream should send")?;

    let mut streams = Vec::new();
    for _ in 0..2 {
        streams.push(accept_stream(&server_conn).await?);
    }
    let kept_index = streams
        .iter()
        .position(|(kind, _, _)| *kind == u32::from(RawEventKind::Log))
        .context("the Log stream should arrive")?;
    let (_, mut kept_send, mut kept_recv) = streams.swap_remove(kept_index);
    let (reset_kind, _reset_send, mut reset_recv) =
        streams.pop().context("the Dns stream should arrive")?;
    ensure!(reset_kind == u32::from(RawEventKind::Dns));
    ensure!(recv_batch(&mut reset_recv).await? == reset_batch.to_vec());
    ensure!(recv_batch(&mut kept_recv).await? == kept_batch.to_vec());
    ack(&mut kept_send, 2).await?;
    ensure!(timeout(TEST_TIMEOUT, kept_acks.recv()).await? == Some(2));

    // Reset the first stream; the second keeps sending on the connection.
    reset_stream.abort().await;
    let mut buf = [0_u8; 64];
    let read = timeout(TEST_TIMEOUT, reset_recv.read(&mut buf)).await?;
    ensure!(
        matches!(read, Err(ReadError::Reset(_))),
        "the reset stream must end with a reset, not a close marker: {read:?}"
    );
    for timestamp in 3..6 {
        let batch = [(timestamp, format!("kept-{timestamp}").into_bytes())];
        kept_stream.send_batch(&batch).await?;
        ensure!(recv_batch(&mut kept_recv).await? == batch.to_vec());
    }
    ack(&mut kept_send, 5).await?;
    ensure!(timeout(TEST_TIMEOUT, kept_acks.recv()).await? == Some(5));

    // Later close the second stream with its close marker and close ACK.
    let close = tokio::spawn(async move {
        let close = kept_stream.close().await;
        (kept_stream, close)
    });
    let marker = recv_batch(&mut kept_recv).await?;
    ensure!(marker.len() == 1);
    ensure!(marker.first().map(|(ts, _)| *ts) == Some(CHANNEL_CLOSE_TIMESTAMP));
    ack(&mut kept_send, CHANNEL_CLOSE_TIMESTAMP).await?;
    let (_kept_stream, close) = timeout(TEST_TIMEOUT, close).await??;
    ensure!(close? == CloseAck::Received);
    ensure!(kept_acks.try_recv() == Some(CHANNEL_CLOSE_TIMESTAMP));

    // Neither the reset nor the close touched the connection.
    ensure!(server_conn.close_reason().is_none());
    ensure!(connection.generation() == 0);
    ensure!(
        !connects_from(
            &server_endpoint,
            server_conn.remote_address(),
            Duration::from_millis(500),
        )
        .await,
        "the streams must share one connection"
    );

    connection.close().await;
    let reason = timeout(TEST_TIMEOUT, server_conn.closed()).await?;
    ensure!(
        matches!(
            &reason,
            quinn::ConnectionError::ApplicationClosed(close) if &close.reason[..] == b"log_done"
        ),
        "the owner closes the connection: {reason:?}"
    );
    Ok(())
}
