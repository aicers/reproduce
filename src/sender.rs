//! Sending raw events to a Giganto ingest server.
//!
//! A [`GigantoConnection`] owns one QUIC connection: its endpoint, TLS
//! material reload, connect and reconnect. A [`GigantoStream`] is one
//! bidirectional stream on that connection: record header, batches, ACKs and
//! close. Several streams can share one connection, so one Giganto sensor is
//! registered once however many collectors send. [`GigantoSender`] is the
//! one-connection, one-stream pairing local mode uses.

mod connection;
mod stream;
#[cfg(test)]
mod test_support;

use std::{fs, net::SocketAddr, path::Path, sync::Arc, time::Duration};

use anyhow::Error as AnyhowError;
use giganto_client::{
    RawEventKind,
    connection::{HandshakeError, client_handshake},
    frame::SendError,
};
use quinn::{Connection, Endpoint, TransportConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use tracing::info;

pub use self::connection::{ConnectionConfig, GigantoConnection, StreamErrorPolicy};
pub use self::stream::{AckDelivery, AckReceiver, CloseAck, GigantoStream};
use crate::reload::ReloadSignal;

/// Limits how long closing a stream waits for the server's channel-close ACK
/// before finishing the stream anyway.
pub const CHANNEL_CLOSE_TIMEOUT: Duration = Duration::from_secs(15);

/// Defines the sentinel payload sent to signal that a channel is done.
pub const CHANNEL_CLOSE_MESSAGE: &[u8; 12] = b"channel done";

/// Defines the sentinel timestamp used for channel-close messages and finish ACKs.
pub const CHANNEL_CLOSE_TIMESTAMP: i64 = -1;

/// Defines the minimum Giganto server version that this client is compatible with.
pub const REQUIRED_GIGANTO_VERSION: &str = "0.28.0";

/// Defines the keep-alive and reconnect interval in seconds.
pub const INTERVAL: u64 = 5;

/// Limits the maximum number of events to accumulate before flushing a batch.
pub const BATCH_SIZE: usize = 100;

/// Selects how the connect helper should react to QUIC handshake/idle
/// timeouts (`quinn::ConnectionError::TimedOut`).
///
/// `RetryForever` matches the legacy behavior used for the
/// last-known-good endpoint: when the server is briefly unreachable, the
/// helper sleeps for `INTERVAL` seconds and retries indefinitely so the
/// daemon eventually reconnects on its own.
///
/// `ReturnOnTimeout` is used for the reload candidate path. A failed
/// reload must not strand the daemon retrying the candidate forever —
/// surfacing the timeout lets the reconnect fall back to the
/// last-known-good endpoint and report `ReloadDeferred` so the daemon
/// keeps delivering events while the reload retries on a later
/// reconnect.
#[derive(Debug, Clone, Copy)]
enum TimeoutPolicy {
    RetryForever,
    ReturnOnTimeout,
}

/// Categorizes the outcome of a successful stream recovery or connection
/// reconnect.
///
/// `Reconnected` means the stream now runs on a connection that reflects
/// the operator's reload intent: either no reload was requested, or a
/// requested reload was fully applied (the rebuilt endpoint completed its
/// handshake, and in local mode opened its stream, and was committed,
/// clearing the connection's reload flag).
/// It is also what a stream gets when another stream had already replaced
/// the connection it failed on.
///
/// `ReloadDeferred` means the connection was re-established against the
/// **last-known-good** endpoint, but a requested reload could not be
/// applied because the rebuilt endpoint failed its handshake or, in local
/// mode, could not open its stream after the handshake. The
/// last-known-good endpoint is kept and the reload flag remains set so a
/// later reconnect can retry the reload with fresh material. This is *not*
/// a fatal error: the daemon must keep running to expose that retry
/// opportunity, which is why this is reported as a successful outcome
/// rather than an error.
///
/// `StreamReopened` means only the stream was replaced, on the connection
/// it already used.
#[derive(Clone, Debug)]
pub enum ReconnectOutcome {
    /// The reconnect fully succeeded, including any pending reload.
    Reconnected,

    /// The reconnect succeeded against the last-known-good endpoint
    /// after the reload candidate failed its handshake or, in local mode,
    /// its stream setup. The carried error
    /// describes why the candidate was rejected, so the caller can log it;
    /// the reload flag remains set.
    ReloadDeferred(Arc<SenderError>),

    /// A new stream was opened on the same, still live, connection.
    StreamReopened,
}

#[derive(Debug, Error)]
pub enum SenderError {
    #[error("failed to connect Giganto")]
    Connect(#[source] quinn::ConnectError),

    #[error("Giganto connection failed")]
    Connection(#[source] quinn::ConnectionError),

    #[error("Giganto handshake failed")]
    Handshake(#[source] HandshakeError),

    #[error("failed to read (cert, key) file. cert_path:{cert}, key_path:{key}")]
    ReadIdentity {
        cert: String,
        key: String,
        #[source]
        source: std::io::Error,
    },

    #[error("no private keys found")]
    MissingPrivateKey,

    #[error("no certificates found in client certificate file: {path}")]
    MissingCertificate { path: String },

    #[error("failed to read root certificate file: {path}")]
    ReadRootCertificate {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("no certificates found in root certificate file: {path}")]
    MissingRootCertificate { path: String },

    #[error("{context}")]
    Context {
        context: &'static str,
        #[source]
        source: AnyhowError,
    },

    #[error("failed to send channel done message")]
    SendFinish,

    /// Finishing the stream failed after its close obtained `close_ack`.
    #[error("failed to finish stream")]
    FinishStream {
        close_ack: CloseAck,
        #[source]
        source: quinn::ClosedStream,
    },

    #[error("{0:?}")]
    Send(#[source] SendError),

    #[error("receive ACK err: {0}")]
    ReceiveAck(giganto_client::frame::RecvError),

    #[error("sender operation cancelled")]
    Cancelled,

    #[error("Giganto connection is closed")]
    Closed,

    /// The error of a reconnect shared by every stream that waited on it.
    #[error(transparent)]
    Reconnect(Arc<SenderError>),
}

impl SenderError {
    fn context(context: &'static str, source: impl Into<AnyhowError>) -> Self {
        Self::Context {
            context,
            source: source.into(),
        }
    }

    /// Returns the error itself, or the error a shared reconnect failed with.
    #[must_use]
    pub fn root(&self) -> &SenderError {
        match self {
            Self::Reconnect(source) => source.root(),
            other => other,
        }
    }
}

/// Sends one stream of raw events over its own Giganto connection, as local
/// mode does: one connection and one stream, every write error reconnecting
/// the connection, and closing the stream closing the connection.
#[derive(Debug)]
pub struct GigantoSender {
    connection: GigantoConnection,
    stream: GigantoStream,
}

impl GigantoSender {
    /// Creates a new `GigantoSender` by establishing a QUIC connection to the
    /// Giganto ingest server and opening a stream on it.
    ///
    /// If the server is temporarily unreachable (`TimedOut`), retries
    /// indefinitely. The connection subscribes to `reload` before it reads
    /// its TLS files; a reload requested from then on rebuilds the endpoint
    /// from fresh cert/key/CA files before the next handshake.
    ///
    /// `sender_token` both cancels connecting and ends the wait for the
    /// close ACK.
    ///
    /// # Errors
    ///
    /// Returns an error if the TLS certificates are invalid, the endpoint
    /// cannot be created, or the handshake with the server fails.
    pub async fn new(
        cert: &str,
        key: &str,
        ca_certs: &[String],
        server_addr: SocketAddr,
        server_name: &str,
        reload: &ReloadSignal,
        sender_token: CancellationToken,
    ) -> std::result::Result<Self, SenderError> {
        let connection = GigantoConnection::connect(
            ConnectionConfig {
                cert: cert.to_owned(),
                key: key.to_owned(),
                ca_certs: ca_certs.to_vec(),
                server_addr,
                server_name: server_name.to_owned(),
            },
            StreamErrorPolicy::Reconnect,
            reload,
            sender_token.clone(),
        )
        .await?;
        let (stream, _) = connection
            .open_stream(sender_token, AckDelivery::LogOnly)
            .await?;
        Ok(Self { connection, stream })
    }

    /// Writes the record header for `protocol` to the stream, or returns
    /// immediately if the stream already carries that kind.
    ///
    /// # Errors
    ///
    /// Returns an error if writing the header to the QUIC stream fails.
    pub async fn send_header(
        &mut self,
        protocol: RawEventKind,
    ) -> std::result::Result<(), SenderError> {
        self.stream.send_header(protocol).await
    }

    /// Sends a batch of `(timestamp, serialized_event)` pairs to the Giganto
    /// server.
    ///
    /// # Errors
    ///
    /// Returns a `SendError` if serialization or writing to the stream fails.
    pub async fn send_batch(&mut self, events: &[(i64, Vec<u8>)]) -> Result<(), SendError> {
        self.stream.send_batch(events).await
    }

    /// Closes the connection, reconnects, and opens a new stream that needs
    /// its record header again.
    ///
    /// A pending reload is committed only once the stream opens on the
    /// rebuilt endpoint; if it cannot, the stream is opened on a connection
    /// made with the last-known-good endpoint and the reload stays pending,
    /// reported as [`ReconnectOutcome::ReloadDeferred`].
    ///
    /// # Errors
    ///
    /// Returns an error when the reconnect cannot produce a working
    /// connection by any path, or is cancelled.
    pub async fn reconnect(&mut self) -> std::result::Result<ReconnectOutcome, SenderError> {
        self.stream.recover().await
    }

    /// Gracefully finishes the stream by sending the channel-close sentinel
    /// and waiting for the server to acknowledge, then closes the connection
    /// and waits for the endpoint to become idle.
    ///
    /// If no ACK is received within [`CHANNEL_CLOSE_TIMEOUT`], the connection
    /// is closed anyway. When the stream has no record header, the
    /// channel-close sentinel is skipped: the marker is only sent on a stream
    /// that has already emitted a raw event kind header.
    ///
    /// # Errors
    ///
    /// Returns an error if the channel-close message cannot be sent or the
    /// stream cannot be finished.
    pub async fn finish(&mut self) -> std::result::Result<(), SenderError> {
        self.stream.close().await?;
        self.connection.close().await;
        info!("Data Store ended");
        Ok(())
    }
}

/// Connects to the server and completes the Giganto handshake.
async fn connect_and_handshake(
    endpoint: &Endpoint,
    server_addr: SocketAddr,
    server_name: &str,
    timeout_policy: TimeoutPolicy,
    token: &CancellationToken,
) -> std::result::Result<Connection, SenderError> {
    let conn =
        connect_with_retry(endpoint, server_addr, server_name, timeout_policy, token).await?;
    tokio::select! {
        result = client_handshake(&conn, REQUIRED_GIGANTO_VERSION) => {
            result.map_err(SenderError::Handshake)?;
        }
        () = token.cancelled() => return Err(SenderError::Cancelled),
    }
    Ok(conn)
}

/// Connects to the server, dispatching on the configured `TimeoutPolicy`
/// to either retry forever (legacy behavior, used for the last-known-good
/// endpoint) or surface the timeout (used for reload-candidate connects so
/// a reconnect can fall back without looping forever).
async fn connect_with_retry(
    endpoint: &Endpoint,
    server_addr: SocketAddr,
    server_name: &str,
    timeout_policy: TimeoutPolicy,
    token: &CancellationToken,
) -> std::result::Result<Connection, SenderError> {
    loop {
        let connecting = endpoint
            .connect(server_addr, server_name)
            .map_err(SenderError::Connect)?;
        let result = tokio::select! {
            result = connecting => result,
            () = token.cancelled() => return Err(SenderError::Cancelled),
        };
        match result {
            Ok(conn) => return Ok(conn),
            Err(quinn::ConnectionError::TimedOut) => match timeout_policy {
                TimeoutPolicy::RetryForever => {
                    info!("Server timeout, reconnecting...");
                    tokio::select! {
                        () = tokio::time::sleep(Duration::from_secs(INTERVAL)) => {}
                        () = token.cancelled() => return Err(SenderError::Cancelled),
                    }
                }
                TimeoutPolicy::ReturnOnTimeout => {
                    return Err(SenderError::Connection(quinn::ConnectionError::TimedOut));
                }
            },
            Err(error) => return Err(SenderError::Connection(error)),
        }
    }
}

/// Creates a QUIC client `Endpoint` configured with the given TLS
/// certificate, private key, and CA root certificates.
///
/// # Errors
///
/// Returns an error if the certificate or key files cannot be read, parsed,
/// or if the TLS configuration is invalid.
fn create_endpoint(
    cert: &str,
    key: &str,
    ca_certs: &[String],
) -> std::result::Result<Endpoint, SenderError> {
    let (cert_pem, key_pem) = read_identity_files(cert, key)?;
    let pv_key = parse_private_key(key, key_pem)?;
    let cert_chain = parse_cert_chain(cert, cert_pem)?;
    let server_root = to_root_cert(ca_certs)?;
    let client_config = build_client_config(server_root, cert_chain, pv_key)?;

    let any_addr = SocketAddr::from(([0_u16; 8], 0));
    let mut endpoint = quinn::Endpoint::client(any_addr)
        .map_err(|source| SenderError::context("failed to create QUIC endpoint", source))?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

/// Reads the client certificate and key files from disk.
fn read_identity_files(
    cert: &str,
    key: &str,
) -> std::result::Result<(Vec<u8>, Vec<u8>), SenderError> {
    let cert_pem = fs::read(cert).map_err(|source| SenderError::ReadIdentity {
        cert: cert.to_string(),
        key: key.to_string(),
        source,
    })?;
    let key_pem = fs::read(key).map_err(|source| SenderError::ReadIdentity {
        cert: cert.to_string(),
        key: key.to_string(),
        source,
    })?;
    Ok((cert_pem, key_pem))
}

/// Parses the private key from DER or PEM bytes.
fn parse_private_key(
    key_path: &str,
    key_pem: Vec<u8>,
) -> std::result::Result<PrivateKeyDer<'static>, SenderError> {
    if Path::new(key_path)
        .extension()
        .is_some_and(|ext| ext == "der")
    {
        Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pem)))
    } else {
        rustls_pemfile::private_key(&mut &*key_pem)
            .map_err(|source| SenderError::context("malformed PKCS #1 private key", source))?
            .ok_or(SenderError::MissingPrivateKey)
    }
}

/// Parses the client certificate chain from DER or PEM bytes.
fn parse_cert_chain(
    cert_path: &str,
    cert_pem: Vec<u8>,
) -> std::result::Result<Vec<CertificateDer<'static>>, SenderError> {
    let cert_chain = if Path::new(cert_path)
        .extension()
        .is_some_and(|ext| ext == "der")
    {
        vec![CertificateDer::from(cert_pem)]
    } else {
        rustls_pemfile::certs(&mut &*cert_pem)
            .collect::<std::result::Result<_, _>>()
            .map_err(|source| SenderError::context("invalid PEM-encoded certificate", source))?
    };

    if cert_chain.is_empty() {
        return Err(SenderError::MissingCertificate {
            path: cert_path.to_string(),
        });
    }

    Ok(cert_chain)
}

/// Builds the QUIC client configuration from the parsed TLS materials.
fn build_client_config(
    server_root: rustls::RootCertStore,
    cert_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
) -> std::result::Result<quinn::ClientConfig, SenderError> {
    // Select the same provider as the Manager connection explicitly.
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let client_crypto = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|source| SenderError::context("unsupported TLS protocol versions", source))?
        .with_root_certificates(server_root)
        .with_client_auth_cert(cert_chain, private_key)
        .map_err(|source| {
            SenderError::context("invalid client certificate or private key", source)
        })?;

    let mut transport = TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(INTERVAL)));

    let mut client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
            .map_err(|source| SenderError::context("failed to build QUIC client config", source))?,
    ));
    client_config.transport_config(Arc::new(transport));
    Ok(client_config)
}

/// Builds a `RootCertStore` from a list of PEM-encoded CA certificate file
/// paths.
///
/// # Errors
///
/// Returns an error if any certificate file cannot be read or contains
/// invalid PEM data.
fn to_root_cert(
    ca_certs_paths: &[String],
) -> std::result::Result<rustls::RootCertStore, SenderError> {
    let mut root_cert = rustls::RootCertStore::empty();
    for ca_cert in ca_certs_paths {
        let file = fs::read(ca_cert).map_err(|source| SenderError::ReadRootCertificate {
            path: ca_cert.clone(),
            source,
        })?;
        let root_certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut &*file)
            .collect::<std::result::Result<_, _>>()
            .map_err(|source| SenderError::context("invalid PEM-encoded certificate", source))?;
        if root_certs.is_empty() {
            return Err(SenderError::MissingRootCertificate {
                path: ca_cert.clone(),
            });
        }
        for cert in root_certs {
            root_cert
                .add(cert)
                .map_err(|source| SenderError::context("failed to add root cert", source))?;
        }
    }

    Ok(root_cert)
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        path::{Path, PathBuf},
        sync::Arc,
    };

    use anyhow::{Context, Result};
    use giganto_client::{
        connection::{HandshakeError, server_handshake},
        frame::recv_raw,
        ingest::receive_record_header,
    };
    use quinn::{IdleTimeout, VarInt};
    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose};
    use tempfile::tempdir;
    use tokio::time::{Duration, timeout};

    use super::test_support::{
        RECONNECT_TIMEOUT, ServerSession, TEST_CERT_PEM, TEST_KEY_PEM, TEST_ROOT_PEM,
        TEST_SERVER_NAME, TEST_TIMEOUT, accept_connection, accept_server_stream,
        build_server_endpoint, fixture_path, load_cert_chain, load_private_key,
    };
    use super::*;

    /// Creates a [`GigantoSender`] against a fresh in-process test server.
    async fn connect_test_sender(
        token: CancellationToken,
    ) -> Result<(GigantoSender, ServerSession)> {
        let (server_endpoint, server_addr) = build_server_endpoint()?;
        let cert = fixture_path(TEST_CERT_PEM);
        let key = fixture_path(TEST_KEY_PEM);
        let roots = [fixture_path(TEST_ROOT_PEM)];
        let reload = ReloadSignal::new();
        let (sender, connection) = tokio::join!(
            GigantoSender::new(
                &cert,
                &key,
                &roots,
                server_addr,
                TEST_SERVER_NAME,
                &reload,
                token,
            ),
            accept_connection(&server_endpoint, TEST_TIMEOUT),
        );
        Ok((
            sender.context("test sender should connect to the test server")?,
            ServerSession {
                server_endpoint,
                connection: connection?,
            },
        ))
    }

    async fn connect_stream_sender() -> Result<(GigantoSender, ServerSession)> {
        connect_test_sender(CancellationToken::new()).await
    }

    #[test]
    fn to_root_cert_returns_empty_store_for_empty_input() {
        let store = to_root_cert(&[]).expect("empty CA list should be valid");
        assert!(store.is_empty());
    }

    #[test]
    fn to_root_cert_loads_valid_pem_certificate() {
        let root = fixture_path(TEST_ROOT_PEM);
        let store = to_root_cert(&[root]).expect("fixture root certificate should load");
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn to_root_cert_loads_each_root_certificate_file() {
        let root = fixture_path(TEST_ROOT_PEM);
        let store = to_root_cert(&[root.clone(), root])
            .expect("each configured root certificate file should be loaded");
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn to_root_cert_rejects_invalid_pem() {
        let dir = tempdir().expect("tempdir should be created");
        let invalid_path = dir.path().join("invalid-root.pem");
        std::fs::write(&invalid_path, b"not a pem").expect("invalid pem fixture should be written");

        let err = to_root_cert(&[invalid_path.to_string_lossy().into_owned()])
            .expect_err("invalid root PEM must be rejected");
        assert!(
            err.to_string()
                .contains("no certificates found in root certificate file")
        );
    }

    #[test]
    fn to_root_cert_rejects_empty_pem_file() {
        let dir = tempdir().expect("tempdir should be created");
        let empty_path = dir.path().join("empty-root.pem");
        std::fs::write(&empty_path, b"").expect("empty root PEM fixture should be written");

        let err = to_root_cert(&[empty_path.to_string_lossy().into_owned()])
            .expect_err("empty root PEM must be rejected");
        assert!(
            err.to_string()
                .contains("no certificates found in root certificate file")
        );
    }

    #[test]
    fn create_endpoint_rejects_missing_certificate_files() {
        let err = create_endpoint("missing-cert.pem", "missing-key.pem", &[])
            .expect_err("missing certificate paths must fail");
        assert!(err.to_string().contains("failed to read (cert, key) file"));
    }

    #[tokio::test]
    async fn create_endpoint_loads_valid_pem_material() {
        let cert = fixture_path(TEST_CERT_PEM);
        let key = fixture_path(TEST_KEY_PEM);
        let root = fixture_path(TEST_ROOT_PEM);

        let endpoint = create_endpoint(&cert, &key, &[root])
            .expect("fixture certificate bundle should create a client endpoint");
        drop(endpoint);
    }

    #[tokio::test]
    async fn create_endpoint_rejects_invalid_certificate_pem() {
        let dir = tempdir().expect("tempdir should be created");
        let cert_path = dir.path().join("invalid-cert.pem");
        let key_path = PathBuf::from(fixture_path(TEST_KEY_PEM));
        let root_path = fixture_path(TEST_ROOT_PEM);
        std::fs::write(&cert_path, b"not a certificate")
            .expect("invalid certificate fixture should be written");

        let err = create_endpoint(
            &cert_path.to_string_lossy(),
            key_path
                .to_str()
                .expect("fixture key path must be valid UTF-8"),
            &[root_path],
        )
        .expect_err("invalid certificate PEM must be rejected");
        assert!(
            err.to_string()
                .contains("no certificates found in client certificate file")
        );
    }

    #[tokio::test]
    async fn create_endpoint_rejects_empty_certificate_pem() {
        let dir = tempdir().expect("tempdir should be created");
        let cert_path = dir.path().join("empty-cert.pem");
        let key_path = PathBuf::from(fixture_path(TEST_KEY_PEM));
        let root_path = fixture_path(TEST_ROOT_PEM);
        std::fs::write(&cert_path, b"").expect("empty certificate fixture should be written");

        let err = create_endpoint(
            &cert_path.to_string_lossy(),
            key_path
                .to_str()
                .expect("fixture key path must be valid UTF-8"),
            &[root_path],
        )
        .expect_err("empty certificate PEM must be rejected");
        assert!(
            err.to_string()
                .contains("no certificates found in client certificate file")
        );
    }

    #[tokio::test]
    async fn create_endpoint_loads_valid_der_certificate() {
        let dir = tempdir().expect("tempdir should be created");
        let cert_der_path = dir.path().join("cert.der");
        let key = fixture_path(TEST_KEY_PEM);
        let root = fixture_path(TEST_ROOT_PEM);
        let cert_chain = load_cert_chain(Path::new(&fixture_path(TEST_CERT_PEM)))
            .expect("fixture certificate should parse as PEM");

        fs::write(
            &cert_der_path,
            cert_chain
                .first()
                .expect("fixture certificate chain should contain one leaf")
                .as_ref(),
        )
        .expect("DER certificate fixture should be written");
        let endpoint = create_endpoint(
            cert_der_path
                .to_str()
                .expect("DER certificate path must be valid UTF-8"),
            &key,
            &[root],
        )
        .expect("DER certificate bundle should create a client endpoint");
        drop(endpoint);
    }

    #[tokio::test]
    async fn create_endpoint_rejects_non_pkcs8_private_key_der() {
        let dir = tempdir().expect("tempdir should be created");
        let key_der_path = dir.path().join("key.der");
        let cert = fixture_path(TEST_CERT_PEM);
        let root = fixture_path(TEST_ROOT_PEM);
        let private_key = load_private_key(Path::new(&fixture_path(TEST_KEY_PEM)))
            .expect("fixture private key should parse as PEM");

        fs::write(&key_der_path, private_key.secret_der())
            .expect("DER private key fixture should be written");

        let err = create_endpoint(
            &cert,
            key_der_path
                .to_str()
                .expect("DER private key path must be valid UTF-8"),
            &[root],
        )
        .expect_err("non-PKCS8 DER keys must be rejected");
        assert!(
            err.to_string()
                .contains("invalid client certificate or private key")
        );
    }

    #[tokio::test]
    async fn create_endpoint_rejects_empty_private_key_pem() {
        let dir = tempdir().expect("tempdir should be created");
        let key_path = dir.path().join("empty-key.pem");
        let cert = fixture_path(TEST_CERT_PEM);
        let root = fixture_path(TEST_ROOT_PEM);
        fs::write(&key_path, b"").expect("empty private key fixture should be written");

        let err = create_endpoint(
            &cert,
            key_path
                .to_str()
                .expect("private key path must be valid UTF-8"),
            &[root],
        )
        .expect_err("empty private key PEM must be rejected");
        assert!(err.to_string().contains("no private keys found"));
    }

    #[tokio::test]
    async fn send_header_writes_header_to_stream() {
        let (mut sender, session) = connect_stream_sender()
            .await
            .expect("sender should connect to the test server");

        assert!(
            sender.stream.current_stream_kind().is_none(),
            "a freshly-created sender must start without a header on the stream",
        );
        sender
            .send_header(RawEventKind::Dns)
            .await
            .expect("header send should succeed");
        assert_eq!(
            sender.stream.current_stream_kind(),
            Some(RawEventKind::Dns),
            "a successful header send should record the kind on the stream",
        );
        let (_server_send, mut server_recv) = accept_server_stream(&session.connection)
            .await
            .expect("server should observe the sender stream after a header write");
        let mut header = [0_u8; std::mem::size_of::<u32>()];
        receive_record_header(&mut server_recv, &mut header)
            .await
            .expect("server should receive the first record header");
        assert_eq!(header, u32::from(RawEventKind::Dns).to_le_bytes());
    }

    #[tokio::test]
    async fn send_header_is_no_op_for_same_kind() {
        let (mut sender, session) = connect_stream_sender()
            .await
            .expect("sender should connect to the test server");

        sender
            .send_header(RawEventKind::Dns)
            .await
            .expect("first header send should succeed");
        let (_server_send, mut server_recv) = accept_server_stream(&session.connection)
            .await
            .expect("server should observe the sender stream after a header write");
        let mut header = [0_u8; std::mem::size_of::<u32>()];
        receive_record_header(&mut server_recv, &mut header)
            .await
            .expect("server should receive the first record header");
        assert_eq!(header, u32::from(RawEventKind::Dns).to_le_bytes());

        sender
            .send_header(RawEventKind::Dns)
            .await
            .expect("second header send for the same kind should be a no-op");
        assert_eq!(
            sender.stream.current_stream_kind(),
            Some(RawEventKind::Dns),
            "a no-op header send must leave the recorded kind unchanged",
        );
        let mut duplicate_header = [0_u8; std::mem::size_of::<u32>()];
        assert!(
            timeout(
                Duration::from_millis(100),
                receive_record_header(&mut server_recv, &mut duplicate_header),
            )
            .await
            .is_err(),
            "a same-kind send_header must not write a second header on the same stream",
        );
    }

    #[tokio::test]
    async fn send_header_writes_new_header_for_different_kind() {
        let (mut sender, session) = connect_stream_sender()
            .await
            .expect("sender should connect to the test server");

        sender
            .send_header(RawEventKind::Dns)
            .await
            .expect("first header send should succeed");
        let (_server_send, mut server_recv) = accept_server_stream(&session.connection)
            .await
            .expect("server should observe the sender stream after a header write");
        let mut first_header = [0_u8; std::mem::size_of::<u32>()];
        receive_record_header(&mut server_recv, &mut first_header)
            .await
            .expect("server should receive the first record header");
        assert_eq!(first_header, u32::from(RawEventKind::Dns).to_le_bytes());

        sender
            .send_header(RawEventKind::Http)
            .await
            .expect("send_header with a different kind should write a new header");
        assert_eq!(
            sender.stream.current_stream_kind(),
            Some(RawEventKind::Http),
            "a kind switch must update the recorded current_stream_kind",
        );
        let mut second_header = [0_u8; std::mem::size_of::<u32>()];
        receive_record_header(&mut server_recv, &mut second_header)
            .await
            .expect("server should receive the second record header");
        assert_eq!(second_header, u32::from(RawEventKind::Http).to_le_bytes());
    }

    #[tokio::test]
    async fn send_batch_serializes_events_for_transport() {
        let (mut sender, session) = connect_stream_sender()
            .await
            .expect("sender should connect to the test server");
        let events = vec![(42_i64, b"hello".to_vec()), (43_i64, b"world".to_vec())];

        sender
            .send_batch(&events)
            .await
            .expect("event batch should be written to the stream");
        let (_server_send, mut server_recv) = accept_server_stream(&session.connection)
            .await
            .expect("server should observe the sender stream after a batch write");

        let mut buf = Vec::new();
        recv_raw(&mut server_recv, &mut buf)
            .await
            .expect("server should receive the framed batch");
        let received: Vec<(i64, Vec<u8>)> =
            bincode::deserialize(&buf).expect("server batch payload should deserialize");
        assert_eq!(received, events);
    }

    #[tokio::test]
    async fn finish_sends_channel_done_and_waits_for_ack() {
        let (mut sender, session) = connect_stream_sender()
            .await
            .expect("sender should connect to the test server");

        sender
            .send_header(RawEventKind::Dns)
            .await
            .expect("header send should succeed before finish");
        let finish_handle = tokio::spawn(async move { sender.finish().await });
        let (mut server_send, mut server_recv) = accept_server_stream(&session.connection)
            .await
            .expect("server should observe the sender stream after finish starts");

        let mut header = [0_u8; std::mem::size_of::<u32>()];
        receive_record_header(&mut server_recv, &mut header)
            .await
            .expect("server should receive the record header before the close marker");
        assert_eq!(header, u32::from(RawEventKind::Dns).to_le_bytes());

        let mut buf = Vec::new();
        recv_raw(&mut server_recv, &mut buf)
            .await
            .expect("server should receive the channel-close batch");
        let received: Vec<(i64, Vec<u8>)> =
            bincode::deserialize(&buf).expect("channel-close batch should deserialize");
        let close_record = received
            .first()
            .expect("channel-close batch should contain exactly one record");
        assert_eq!(received.len(), 1);
        assert_eq!(close_record.0, CHANNEL_CLOSE_TIMESTAMP);
        assert_eq!(
            close_record.1,
            bincode::serialize(CHANNEL_CLOSE_MESSAGE)
                .expect("channel-close sentinel payload should serialize"),
        );

        server_send
            .write_all(&CHANNEL_CLOSE_TIMESTAMP.to_be_bytes())
            .await
            .expect("server should send the close ACK");
        finish_handle
            .await
            .expect("finish task should join cleanly")
            .expect("finish should return after receiving the close ACK");

        let reason = timeout(TEST_TIMEOUT, session.connection.closed())
            .await
            .expect("finish should close the connection");
        assert!(
            matches!(
                &reason,
                quinn::ConnectionError::ApplicationClosed(close) if &close.reason[..] == b"log_done"
            ),
            "finish must close the connection with log_done, got {reason:?}",
        );
    }

    #[tokio::test]
    async fn finish_skips_close_marker_when_stream_has_no_header() {
        let (mut sender, session) = connect_stream_sender()
            .await
            .expect("sender should connect to the test server");

        // Open the stream on the server side by sending a header, then clear
        // the recorded kind to model the post-reconnect-no-header state the
        // pipeline leaves behind when shutdown is observed during header
        // recovery. The server has the stream open, so we can observe whether
        // finish writes any record payload before shutting down.
        sender
            .send_header(RawEventKind::Dns)
            .await
            .expect("header send should succeed before clearing the kind");
        let (_server_send, mut server_recv) = accept_server_stream(&session.connection)
            .await
            .expect("server should accept the sender stream after the header write");
        let mut header = [0_u8; std::mem::size_of::<u32>()];
        receive_record_header(&mut server_recv, &mut header)
            .await
            .expect("server should receive the original header");
        assert_eq!(header, u32::from(RawEventKind::Dns).to_le_bytes());

        sender.stream.set_current_stream_kind(None);
        sender
            .finish()
            .await
            .expect("finish on a header-less stream should succeed");

        // No record payload should follow the header — finish must not have
        // written the channel-close marker on a stream the receiver could no
        // longer route to a record kind. Either a clean stream-finish or a
        // connection-closed error proves no payload was sent.
        let mut buf = Vec::new();
        let outcome = recv_raw(&mut server_recv, &mut buf).await;
        assert!(
            outcome.is_err(),
            "finish on a header-less stream must not emit a record payload; \
             got payload of {} bytes",
            buf.len(),
        );
    }

    #[tokio::test]
    async fn finish_cancels_and_drains_owned_ack_task() {
        let (mut sender, _session) = connect_stream_sender()
            .await
            .expect("sender should connect to the test server");
        let ack_task_token = sender
            .stream
            .ack_task_token()
            .expect("sender should own the ACK receiver task before finish");

        sender
            .finish()
            .await
            .expect("finish should drain the ACK receiver task");

        assert!(
            !sender.stream.is_open(),
            "finish must consume the stream and its joined ACK receiver",
        );
        assert!(
            ack_task_token.is_cancelled(),
            "finish must cancel the current ACK receiver token",
        );
    }

    #[tokio::test]
    async fn reconnect_cancels_old_ack_task_before_installing_new_stream() {
        let (mut sender, session) = connect_stream_sender()
            .await
            .expect("sender should connect to the test server");
        let old_ack_token = sender
            .stream
            .ack_task_token()
            .expect("sender should own an ACK receiver task");

        let server_task = tokio::spawn(async move {
            accept_connection(&session.server_endpoint, RECONNECT_TIMEOUT).await
        });

        sender
            .reconnect()
            .await
            .expect("compatible server should allow reconnect");
        server_task
            .await
            .expect("server reconnect task should join cleanly")
            .expect("server reconnect handshake should succeed");

        assert!(
            old_ack_token.is_cancelled(),
            "reconnect must cancel the old ACK receiver token",
        );
        let new_ack_token = sender
            .stream
            .ack_task_token()
            .expect("reconnect should leave the new stream's ACK task tracked");
        assert!(
            !new_ack_token.is_cancelled(),
            "new stream ACK receiver token should remain active after reconnect",
        );
        assert_eq!(sender.connection.generation(), 1);
    }

    #[tokio::test]
    async fn reconnect_on_live_connection_still_replaces_it_in_local_mode() {
        let (mut sender, session) = connect_stream_sender()
            .await
            .expect("sender should connect to the test server");
        let old_connection = session.connection.clone();

        let server_task = tokio::spawn(async move {
            accept_connection(&session.server_endpoint, RECONNECT_TIMEOUT).await
        });
        let outcome = sender
            .reconnect()
            .await
            .expect("compatible server should allow reconnect");
        server_task
            .await
            .expect("server reconnect task should join cleanly")
            .expect("server reconnect handshake should succeed");

        assert!(matches!(outcome, ReconnectOutcome::Reconnected));
        let reason = timeout(TEST_TIMEOUT, old_connection.closed())
            .await
            .expect("local mode must close the connection a write error was seen on");
        assert!(
            matches!(
                &reason,
                quinn::ConnectionError::ApplicationClosed(close) if &close.reason[..] == b"reconnect"
            ),
            "the replaced connection must be closed with reconnect, got {reason:?}",
        );
    }

    #[tokio::test]
    async fn finish_is_idempotent_after_cancelled_reconnect_closes_stream() {
        let token = CancellationToken::new();
        let (mut sender, _session) = connect_test_sender(token.clone())
            .await
            .expect("sender should connect to the test server");
        sender
            .send_header(RawEventKind::Dns)
            .await
            .expect("header send should succeed before reconnect");

        token.cancel();
        let err = sender
            .reconnect()
            .await
            .expect_err("cancelled reconnect must report cancellation");
        assert!(
            matches!(err, SenderError::Cancelled),
            "unexpected reconnect error: {err:?}",
        );

        timeout(TEST_TIMEOUT, sender.finish())
            .await
            .expect("finish after reconnect cancellation should return at once")
            .expect("finish after reconnect cancellation should be idempotent");
    }

    #[tokio::test]
    async fn finish_returns_error_when_close_marker_write_fails() {
        let (mut sender, session) = connect_stream_sender()
            .await
            .expect("sender should connect to the test server");
        sender
            .send_header(RawEventKind::Dns)
            .await
            .expect("header send should succeed before the connection closes");

        session.connection.close(0u32.into(), b"send-finish-error");
        tokio::time::sleep(Duration::from_millis(100)).await;

        let err = sender
            .finish()
            .await
            .expect_err("closed connections must fail when sending the close marker");
        assert!(
            err.to_string()
                .contains("failed to send channel done message")
        );
    }

    #[tokio::test]
    async fn new_returns_handshake_error_for_incompatible_server_version() {
        let (server_endpoint, server_addr) =
            build_server_endpoint().expect("test server endpoint should be created");
        let cert = fixture_path(TEST_CERT_PEM);
        let key = fixture_path(TEST_KEY_PEM);
        let root = fixture_path(TEST_ROOT_PEM);
        let roots = [root];
        let reload = ReloadSignal::new();

        let (sender_result, server_result) = tokio::join!(
            GigantoSender::new(
                &cert,
                &key,
                &roots,
                server_addr,
                TEST_SERVER_NAME,
                &reload,
                CancellationToken::new(),
            ),
            async {
                let incoming = timeout(TEST_TIMEOUT, server_endpoint.accept())
                    .await
                    .context("test server should accept a handshake connection in time")?
                    .context("test server endpoint should stay open while accepting")?;
                let connection = incoming
                    .await
                    .context("sender handshake connection should complete QUIC setup")?;
                let err = server_handshake(&connection, "0.0.1")
                    .await
                    .expect_err("server should reject an incompatible client version");
                Ok::<_, anyhow::Error>(err)
            },
        );

        server_result.expect("server handshake task should complete");
        let err = sender_result.expect_err("incompatible handshake must fail sender creation");
        let SenderError::Handshake(handshake_err) = &err else {
            panic!("sender creation should fail with a handshake error, got {err:?}");
        };
        assert!(
            matches!(
                handshake_err,
                HandshakeError::IncompatibleProtocol(_) | HandshakeError::ReadError(_)
            ),
            "unexpected handshake error: {handshake_err:?}"
        );
    }

    #[tokio::test]
    async fn new_connects_and_opens_a_stream_on_compatible_server() {
        let (mut sender, session) = connect_stream_sender()
            .await
            .expect("compatible server should accept sender creation");

        assert_eq!(sender.connection.generation(), 0);
        assert_eq!(sender.stream.generation(), 0);
        assert_eq!(sender.connection.policy(), StreamErrorPolicy::Reconnect);

        sender
            .send_header(RawEventKind::Dns)
            .await
            .expect("new sender should write a header on its stream");
        let (_server_send, mut server_recv) = accept_server_stream(&session.connection)
            .await
            .expect("server should accept the sender stream after creation");
        let mut header = [0_u8; std::mem::size_of::<u32>()];
        receive_record_header(&mut server_recv, &mut header)
            .await
            .expect("server should receive the sender header");
        assert_eq!(header, u32::from(RawEventKind::Dns).to_le_bytes());
    }

    #[tokio::test]
    async fn reconnect_returns_handshake_error_for_incompatible_server_version() {
        let (mut sender, session) = connect_stream_sender()
            .await
            .expect("sender should connect to the test server");

        let (reconnect_result, server_result) = tokio::join!(sender.reconnect(), async {
            let incoming = timeout(RECONNECT_TIMEOUT, session.server_endpoint.accept())
                .await
                .context("test server should accept a reconnect in time")?
                .context("test server endpoint should stay open while accepting")?;
            let connection = incoming
                .await
                .context("sender reconnect should complete QUIC setup")?;
            let err = server_handshake(&connection, "0.0.1")
                .await
                .expect_err("server should reject an incompatible reconnect version");
            Ok::<_, anyhow::Error>(err)
        },);

        server_result.expect("server reconnect task should complete");
        let err = reconnect_result.expect_err("incompatible reconnect handshake must fail");
        let SenderError::Handshake(handshake_err) = err.root() else {
            panic!("reconnect should fail with a handshake error, got {err:?}");
        };
        assert!(
            matches!(
                handshake_err,
                HandshakeError::IncompatibleProtocol(_) | HandshakeError::ReadError(_)
            ),
            "unexpected reconnect handshake error: {handshake_err:?}"
        );
    }

    #[tokio::test]
    async fn reconnect_reestablishes_the_stream_for_a_fresh_header() {
        let (mut sender, session) = connect_stream_sender()
            .await
            .expect("sender should connect to the test server");

        sender
            .send_header(RawEventKind::Dns)
            .await
            .expect("initial sender should write a header");
        assert_eq!(
            sender.stream.current_stream_kind(),
            Some(RawEventKind::Dns),
            "initial header send should record the stream kind",
        );
        let (_old_send, mut old_recv) = accept_server_stream(&session.connection)
            .await
            .expect("server should accept the original sender stream");
        let mut header = [0_u8; std::mem::size_of::<u32>()];
        receive_record_header(&mut old_recv, &mut header)
            .await
            .expect("server should receive the original header");
        assert_eq!(header, u32::from(RawEventKind::Dns).to_le_bytes());

        let server_task = tokio::spawn(async move {
            accept_connection(&session.server_endpoint, RECONNECT_TIMEOUT).await
        });

        sender
            .reconnect()
            .await
            .expect("compatible server should allow reconnect");
        assert!(
            sender.stream.current_stream_kind().is_none(),
            "reconnect must clear current_stream_kind so the next send_header writes a fresh \
             header on the post-reconnect stream",
        );

        let connection = server_task
            .await
            .expect("server reconnect task should join cleanly")
            .expect("server reconnect handshake should succeed");

        sender
            .send_header(RawEventKind::Dns)
            .await
            .expect("reconnected sender should write a fresh header");
        let (_new_send, mut new_recv) = accept_server_stream(&connection)
            .await
            .expect("server should accept the reconnected sender stream");
        receive_record_header(&mut new_recv, &mut header)
            .await
            .expect("server should receive the header on the new stream");
        assert_eq!(header, u32::from(RawEventKind::Dns).to_le_bytes());
    }

    // ---------------------------------------------------------------
    // Bootroot-style certificate chain helpers and integration tests
    // ---------------------------------------------------------------

    /// Server SAN used in the test PKI, modelling a Bootroot data-store identity.
    const SERVER_SAN: &str = "validation.data-store.localhost.bootroot.test";
    /// Client SAN used in the test PKI, modelling a Bootroot data-broker identity.
    const CLIENT_SAN: &str = "validation.data-broker.localhost.bootroot.test";

    /// Generated Bootroot-style PKI material: root CA -> intermediate CA -> server leaf + client leaf.
    #[allow(clippy::struct_field_names)]
    struct BootrootPki {
        root_ca_pem: String,
        intermediate_ca_pem: String,
        server_cert_pem: String,
        server_key_pem: String,
        client_cert_pem: String,
        client_key_pem: String,
    }

    /// Generates a three-level certificate chain modelling a Bootroot deployment:
    /// `leaf <- intermediate <- root`.
    ///
    /// Two separate leaf certificates are generated:
    /// - A **server** leaf with SAN `validation.data-store.localhost.bootroot.test`
    ///   and `ServerAuth` EKU.
    /// - A **client** leaf with SAN `validation.data-broker.localhost.bootroot.test`
    ///   and `ClientAuth` EKU.
    fn generate_bootroot_pki() -> BootrootPki {
        // Root CA
        let mut root_params =
            CertificateParams::new(Vec::<String>::new()).expect("root CA params should be valid");
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Test Root CA");
        root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let root_key = KeyPair::generate().expect("root CA key should generate");
        let root_cert = root_params
            .self_signed(&root_key)
            .expect("root CA should self-sign");

        // Intermediate CA
        let mut inter_params = CertificateParams::new(Vec::<String>::new())
            .expect("intermediate CA params should be valid");
        inter_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        inter_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Test Intermediate CA");
        inter_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let inter_key = KeyPair::generate().expect("intermediate key should generate");
        let root_issuer = Issuer::from_ca_cert_der(root_cert.der(), &root_key)
            .expect("root issuer should be constructible");
        let inter_cert = inter_params
            .signed_by(&inter_key, &root_issuer)
            .expect("intermediate CA should be signed by root");

        let inter_issuer = Issuer::from_ca_cert_der(inter_cert.der(), &inter_key)
            .expect("intermediate issuer should be constructible");

        // Server leaf (data-store identity)
        let mut server_params = CertificateParams::new(vec![SERVER_SAN.to_string()])
            .expect("server leaf params should be valid");
        server_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, SERVER_SAN);
        server_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        server_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let server_key = KeyPair::generate().expect("server leaf key should generate");
        let server_cert = server_params
            .signed_by(&server_key, &inter_issuer)
            .expect("server leaf should be signed by intermediate");

        // Client leaf (data-broker identity)
        let mut client_params = CertificateParams::new(vec![CLIENT_SAN.to_string()])
            .expect("client leaf params should be valid");
        client_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, CLIENT_SAN);
        client_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        client_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        let client_key = KeyPair::generate().expect("client leaf key should generate");
        let client_cert = client_params
            .signed_by(&client_key, &inter_issuer)
            .expect("client leaf should be signed by intermediate");

        BootrootPki {
            root_ca_pem: root_cert.pem(),
            intermediate_ca_pem: inter_cert.pem(),
            server_cert_pem: server_cert.pem(),
            server_key_pem: server_key.serialize_pem(),
            client_cert_pem: client_cert.pem(),
            client_key_pem: client_key.serialize_pem(),
        }
    }

    /// Writes PEM content to a file inside `dir` and returns the path as a `String`.
    fn write_pem(dir: &Path, name: &str, pem: &str) -> String {
        let path = dir.join(name);
        fs::write(&path, pem).unwrap_or_else(|e| {
            panic!("should write {name}: {e}");
        });
        path.to_string_lossy().into_owned()
    }

    // --- trust-store unit tests for Bootroot-shaped bundles ---

    #[test]
    fn to_root_cert_loads_bootroot_ca_bundle() {
        let pki = generate_bootroot_pki();
        let dir = tempdir().expect("tempdir should be created");

        // Bootroot-style: intermediate + root in one file
        let bundle = format!("{}{}", pki.intermediate_ca_pem, pki.root_ca_pem);
        let bundle_path = write_pem(dir.path(), "ca-bundle.pem", &bundle);

        let store = to_root_cert(&[bundle_path]).expect("Bootroot CA bundle should load");
        assert_eq!(
            store.len(),
            2,
            "both intermediate and root must be in the trust store"
        );
    }

    #[test]
    fn to_root_cert_distinguishes_intermediate_only_from_full_bootroot_bundle() {
        let pki = generate_bootroot_pki();
        let dir = tempdir().expect("tempdir should be created");

        // This store-level test intentionally complements the handshake-level
        // regression checks below. It makes the trust-store shape explicit:
        // an intermediate-only file yields one trust anchor, while the full
        // Bootroot bundle yields both intermediate and root.
        let intermediate_only = write_pem(
            dir.path(),
            "intermediate-only.pem",
            &pki.intermediate_ca_pem,
        );

        let store =
            to_root_cert(&[intermediate_only]).expect("single intermediate PEM should load");
        assert_eq!(
            store.len(),
            1,
            "only the intermediate should be present when root is missing"
        );

        // Now verify that the full bundle has both
        let bundle = format!("{}{}", pki.intermediate_ca_pem, pki.root_ca_pem);
        let bundle_path = write_pem(dir.path(), "ca-bundle.pem", &bundle);
        let full_store = to_root_cert(&[bundle_path]).expect("full bundle should load");
        assert_eq!(
            full_store.len(),
            2,
            "bundle must include both intermediate and root"
        );
    }

    #[test]
    fn to_root_cert_loads_split_ca_files_backward_compat() {
        let pki = generate_bootroot_pki();
        let dir = tempdir().expect("tempdir should be created");

        let root_path = write_pem(dir.path(), "root.pem", &pki.root_ca_pem);
        let inter_path = write_pem(dir.path(), "intermediate.pem", &pki.intermediate_ca_pem);

        let store = to_root_cert(&[root_path, inter_path]).expect("split CA files should load");
        assert_eq!(
            store.len(),
            2,
            "split-file CA input must load both certificates"
        );
    }

    #[test]
    fn to_root_cert_loads_single_root_backward_compat() {
        let pki = generate_bootroot_pki();
        let dir = tempdir().expect("tempdir should be created");
        let root_path = write_pem(dir.path(), "root.pem", &pki.root_ca_pem);

        let store = to_root_cert(&[root_path]).expect("single root CA should load");
        assert_eq!(store.len(), 1);
    }

    // --- endpoint-level integration tests with Bootroot chain ---

    #[tokio::test]
    async fn create_endpoint_with_split_ca_files() {
        let pki = generate_bootroot_pki();
        let dir = tempdir().expect("tempdir should be created");

        let chain = format!("{}{}", pki.client_cert_pem, pki.intermediate_ca_pem);
        let cert_path = write_pem(dir.path(), "client-chain.pem", &chain);
        let key_path = write_pem(dir.path(), "client-key.pem", &pki.client_key_pem);
        let root_path = write_pem(dir.path(), "root.pem", &pki.root_ca_pem);
        let inter_path = write_pem(dir.path(), "intermediate.pem", &pki.intermediate_ca_pem);

        let endpoint = create_endpoint(&cert_path, &key_path, &[root_path, inter_path])
            .expect("split CA files should create endpoint");
        drop(endpoint);
    }

    // --- QUIC/TLS mTLS handshake tests with Bootroot chain ---

    /// Builds a test server that requires mTLS using the Bootroot chain.
    fn build_bootroot_server_endpoint(
        pki: &BootrootPki,
        dir: &Path,
    ) -> Result<(Endpoint, SocketAddr)> {
        let chain_pem = format!("{}{}", pki.server_cert_pem, pki.intermediate_ca_pem);
        let chain_bytes = chain_pem.as_bytes();
        let cert_chain: Vec<CertificateDer> = rustls_pemfile::certs(&mut &*chain_bytes)
            .collect::<std::result::Result<_, _>>()
            .context("server cert chain PEM should parse")?;

        let key_bytes = pki.server_key_pem.as_bytes();
        let private_key = rustls_pemfile::private_key(&mut &*key_bytes)
            .context("server key PEM should parse")?
            .context("server key PEM should contain a key")?;

        // Build client-auth verifier using the CA bundle
        let mut client_roots = rustls::RootCertStore::empty();
        let bundle_pem = format!("{}{}", pki.intermediate_ca_pem, pki.root_ca_pem);
        let bundle_bytes = bundle_pem.as_bytes();
        let ca_certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut &*bundle_bytes)
            .collect::<std::result::Result<_, _>>()
            .context("CA bundle PEM should parse")?;
        for cert in ca_certs {
            client_roots
                .add(cert)
                .context("should add CA cert to client verifier")?;
        }

        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let client_verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(client_roots),
            provider.clone(),
        )
        .build()
        .context("client verifier should build")?;

        let server_crypto = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .context("TLS protocol versions should be supported")?
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(cert_chain, private_key)
            .context("mTLS server config should build")?;

        let _ = dir; // dir kept alive by caller
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
                .context("mTLS QUIC server config should build")?,
        ));
        let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let endpoint = Endpoint::server(server_config, bind_addr)
            .context("mTLS server endpoint should bind")?;
        let addr = endpoint
            .local_addr()
            .context("mTLS server should have a local address")?;
        Ok((endpoint, addr))
    }

    #[tokio::test]
    async fn bootroot_mtls_handshake_succeeds_with_bundled_ca() {
        let pki = generate_bootroot_pki();
        let dir = tempdir().expect("tempdir should be created");

        let (server_endpoint, server_addr) =
            build_bootroot_server_endpoint(&pki, dir.path()).expect("mTLS server should start");

        // Client uses Bootroot-style inputs
        let chain = format!("{}{}", pki.client_cert_pem, pki.intermediate_ca_pem);
        let cert_path = write_pem(dir.path(), "client-chain.pem", &chain);
        let key_path = write_pem(dir.path(), "client-key.pem", &pki.client_key_pem);
        let bundle = format!("{}{}", pki.intermediate_ca_pem, pki.root_ca_pem);
        let ca_path = write_pem(dir.path(), "ca-bundle.pem", &bundle);

        let client_endpoint = create_endpoint(&cert_path, &key_path, &[ca_path])
            .expect("client endpoint should be created");

        let connect = client_endpoint
            .connect(server_addr, SERVER_SAN)
            .expect("client should start connecting");
        let (client_result, server_result) = tokio::join!(
            async { connect.await.context("client TLS handshake") },
            async {
                let incoming = timeout(TEST_TIMEOUT, server_endpoint.accept())
                    .await
                    .context("server should accept in time")?
                    .context("server should stay open")?;
                incoming.await.context("server TLS handshake")
            },
        );

        client_result.expect("Bootroot mTLS client handshake should succeed");
        server_result.expect("Bootroot mTLS server handshake should succeed");
    }

    /// Builds a server that presents only its leaf cert (no chain), so the
    /// client must have both intermediate and root in its trust store to
    /// verify the leaf. This models the regression where only the first PEM
    /// from a bundled CA file was loaded.
    fn build_leaf_only_server_endpoint(
        pki: &BootrootPki,
        _dir: &Path,
    ) -> Result<(Endpoint, SocketAddr)> {
        // Server presents ONLY the server leaf cert (no intermediate in chain).
        let cert_bytes = pki.server_cert_pem.as_bytes();
        let cert_chain: Vec<CertificateDer> = rustls_pemfile::certs(&mut &*cert_bytes)
            .collect::<std::result::Result<_, _>>()
            .context("server leaf cert PEM should parse")?;

        let key_bytes = pki.server_key_pem.as_bytes();
        let private_key = rustls_pemfile::private_key(&mut &*key_bytes)
            .context("leaf key PEM should parse")?
            .context("leaf key PEM should contain a key")?;

        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let server_crypto = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .context("TLS protocol versions should be supported")?
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)
            .context("leaf-only server config should build")?;

        let server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
                .context("leaf-only QUIC server config should build")?,
        ));
        let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let endpoint = Endpoint::server(server_config, bind_addr)
            .context("leaf-only server endpoint should bind")?;
        let addr = endpoint
            .local_addr()
            .context("leaf-only server should have a local address")?;
        Ok((endpoint, addr))
    }

    #[tokio::test]
    async fn bootroot_mtls_fails_with_root_only_in_trust_store() {
        // The server presents only the leaf cert (not a full chain).
        // The client has only the root CA, but NOT the intermediate.
        // Without the intermediate, the client cannot build a path from
        // leaf -> intermediate -> root, so TLS must fail.
        // This catches a regression to first-PEM-only parsing of a bundle
        // where the first cert is the intermediate and the root is dropped.
        let pki = generate_bootroot_pki();
        let dir = tempdir().expect("tempdir should be created");

        let (server_endpoint, server_addr) = build_leaf_only_server_endpoint(&pki, dir.path())
            .expect("leaf-only server should start");

        // Client trusts only root (not intermediate).
        let cert_path = write_pem(dir.path(), "client-cert.pem", &pki.client_cert_pem);
        let key_path = write_pem(dir.path(), "client-key.pem", &pki.client_key_pem);
        let ca_path = write_pem(dir.path(), "root-only.pem", &pki.root_ca_pem);

        let client_endpoint = create_endpoint(&cert_path, &key_path, &[ca_path])
            .expect("client endpoint should be created");

        let connect = client_endpoint
            .connect(server_addr, SERVER_SAN)
            .expect("client should start connecting");
        let (client_result, _server_result) = tokio::join!(connect, async {
            let incoming = timeout(TEST_TIMEOUT, server_endpoint.accept()).await;
            if let Ok(Some(incoming)) = incoming {
                let _ = incoming.await;
            }
        },);

        assert!(
            client_result.is_err(),
            "TLS must fail when server sends leaf-only and client \
             only has root (missing intermediate in trust store)"
        );
    }

    #[tokio::test]
    async fn bootroot_bundled_ca_succeeds_where_root_only_fails() {
        // This is the key regression test: given a server that presents
        // only its leaf, a client with the full Bootroot CA bundle
        // (intermediate + root) MUST succeed, whereas root-only MUST
        // fail. This ensures multi-PEM parsing loads all certs.
        let pki = generate_bootroot_pki();
        let dir = tempdir().expect("tempdir should be created");

        let (server_endpoint, server_addr) = build_leaf_only_server_endpoint(&pki, dir.path())
            .expect("leaf-only server should start");

        // Client has the full Bootroot CA bundle
        let cert_path = write_pem(dir.path(), "client-cert.pem", &pki.client_cert_pem);
        let key_path = write_pem(dir.path(), "client-key.pem", &pki.client_key_pem);
        let bundle = format!("{}{}", pki.intermediate_ca_pem, pki.root_ca_pem);
        let ca_path = write_pem(dir.path(), "ca-bundle.pem", &bundle);

        let client_endpoint = create_endpoint(&cert_path, &key_path, &[ca_path])
            .expect("client endpoint should be created");

        let connect = client_endpoint
            .connect(server_addr, SERVER_SAN)
            .expect("client should start connecting");
        let (client_result, server_result) = tokio::join!(
            async { connect.await.context("client TLS handshake") },
            async {
                let incoming = timeout(TEST_TIMEOUT, server_endpoint.accept())
                    .await
                    .context("server should accept in time")?
                    .context("server should stay open")?;
                incoming.await.context("server TLS handshake")
            },
        );

        client_result.expect(
            "Bootroot CA bundle must allow validation of leaf cert \
             (regression: first-PEM-only would miss the root)",
        );
        server_result.expect("server handshake should complete");
    }

    #[tokio::test]
    async fn bootroot_mtls_handshake_succeeds_with_split_ca_files() {
        let pki = generate_bootroot_pki();
        let dir = tempdir().expect("tempdir should be created");

        let (server_endpoint, server_addr) =
            build_bootroot_server_endpoint(&pki, dir.path()).expect("mTLS server should start");

        let chain = format!("{}{}", pki.client_cert_pem, pki.intermediate_ca_pem);
        let cert_path = write_pem(dir.path(), "client-chain.pem", &chain);
        let key_path = write_pem(dir.path(), "client-key.pem", &pki.client_key_pem);
        let root_path = write_pem(dir.path(), "root.pem", &pki.root_ca_pem);
        let inter_path = write_pem(dir.path(), "intermediate.pem", &pki.intermediate_ca_pem);

        let client_endpoint = create_endpoint(&cert_path, &key_path, &[root_path, inter_path])
            .expect("client endpoint should be created");

        let connect = client_endpoint
            .connect(server_addr, SERVER_SAN)
            .expect("client should start connecting");
        let (client_result, server_result) = tokio::join!(
            async { connect.await.context("client TLS handshake") },
            async {
                let incoming = timeout(TEST_TIMEOUT, server_endpoint.accept())
                    .await
                    .context("server should accept in time")?
                    .context("server should stay open")?;
                incoming.await.context("server TLS handshake")
            },
        );

        client_result.expect("split-CA mTLS client handshake should succeed");
        server_result.expect("split-CA mTLS server handshake should succeed");
    }

    /// Builds a client `Endpoint` whose QUIC `max_idle_timeout` is short
    /// enough that connecting to a non-responsive UDP address times out
    /// within a test budget instead of the default ~30 s. Used by the
    /// `TimeoutPolicy` regression tests.
    fn build_short_idle_client_endpoint() -> Result<Endpoint> {
        let cert_path = fixture_path(TEST_CERT_PEM);
        let key_path = fixture_path(TEST_KEY_PEM);
        let root_path = fixture_path(TEST_ROOT_PEM);

        let (cert_pem, key_pem) =
            read_identity_files(&cert_path, &key_path).context("fixture identity should load")?;
        let pv_key =
            parse_private_key(&key_path, key_pem).context("fixture private key should parse")?;
        let cert_chain = parse_cert_chain(&cert_path, cert_pem)
            .context("fixture certificate chain should parse")?;
        let server_root =
            to_root_cert(&[root_path]).context("fixture root certificate should load")?;
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let client_crypto = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .context("TLS protocol versions should be supported")?
            .with_root_certificates(server_root)
            .with_client_auth_cert(cert_chain, pv_key)
            .context("fixture client config should build")?;

        let mut transport = TransportConfig::default();
        let idle = IdleTimeout::from(VarInt::from_u32(500));
        transport.max_idle_timeout(Some(idle));

        let mut client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
                .context("short-idle QUIC client config should build")?,
        ));
        client_config.transport_config(Arc::new(transport));

        let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let mut endpoint =
            quinn::Endpoint::client(bind_addr).context("short-idle client endpoint should bind")?;
        endpoint.set_default_client_config(client_config);
        Ok(endpoint)
    }

    /// Regression test for the timeout-shaped reload-candidate failure:
    /// `ReturnOnTimeout` must surface a `quinn::ConnectionError::TimedOut`
    /// instead of looping forever the way `RetryForever` does. Without
    /// this distinction, a hung handshake on the rebuilt reload candidate
    /// would prevent a reconnect from ever falling back to the
    /// last-known-good endpoint.
    #[tokio::test]
    async fn connect_with_retry_returns_on_timeout_when_policy_is_return_on_timeout() {
        let endpoint =
            build_short_idle_client_endpoint().expect("short-idle endpoint should build");

        // Bind a UDP socket that never speaks QUIC. The client handshake
        // gets no response and times out after `max_idle_timeout`.
        let dummy_socket =
            std::net::UdpSocket::bind("127.0.0.1:0").expect("dummy UDP socket should bind");
        let dummy_addr = dummy_socket
            .local_addr()
            .expect("dummy UDP socket should have a local address");

        let result = timeout(
            Duration::from_secs(5),
            connect_with_retry(
                &endpoint,
                dummy_addr,
                TEST_SERVER_NAME,
                TimeoutPolicy::ReturnOnTimeout,
                &CancellationToken::new(),
            ),
        )
        .await
        .expect("ReturnOnTimeout policy must surface the timeout instead of retrying forever");

        match result {
            Err(SenderError::Connection(quinn::ConnectionError::TimedOut)) => {}
            other => {
                panic!("ReturnOnTimeout must report a TimedOut connection error, got {other:?}")
            }
        }
    }

    #[tokio::test]
    async fn connect_and_handshake_returns_cancelled_while_waiting_for_app_handshake() {
        let (server_endpoint, server_addr) =
            build_server_endpoint().expect("test server endpoint should be created");
        let cert = fixture_path(TEST_CERT_PEM);
        let key = fixture_path(TEST_KEY_PEM);
        let root = fixture_path(TEST_ROOT_PEM);
        let endpoint =
            create_endpoint(&cert, &key, &[root]).expect("client endpoint should be created");
        let token = CancellationToken::new();
        let server_token = token.clone();

        let server_task = tokio::spawn(async move {
            let incoming = timeout(TEST_TIMEOUT, server_endpoint.accept())
                .await
                .context("test server should accept a connection in time")?
                .context("test server endpoint should stay open while accepting")?;
            let connection = incoming
                .await
                .context("client connection should complete QUIC setup")?;
            server_token.cancelled().await;
            drop(connection);
            Ok::<_, anyhow::Error>(())
        });

        tokio::spawn({
            let token = token.clone();
            async move {
                tokio::time::sleep(Duration::from_millis(100)).await;
                token.cancel();
            }
        });

        let result = timeout(
            TEST_TIMEOUT,
            connect_and_handshake(
                &endpoint,
                server_addr,
                TEST_SERVER_NAME,
                TimeoutPolicy::RetryForever,
                &token,
            ),
        )
        .await
        .expect("connect_and_handshake should observe cancellation during the app handshake");

        assert!(
            matches!(result, Err(SenderError::Cancelled)),
            "connect_and_handshake should return SenderError::Cancelled",
        );
        server_task
            .await
            .expect("server task should join cleanly")
            .expect("server task should complete");
    }

    /// Companion to the test above: the legacy `RetryForever` policy must
    /// keep looping on `TimedOut` so transient server outages eventually
    /// reconnect. The outer `tokio::time::timeout` is the assertion: if
    /// the helper returns an error within the budget, the regression
    /// would be that the legacy retry-forever behavior was lost.
    #[tokio::test]
    async fn connect_with_retry_keeps_retrying_when_policy_is_retry_forever() {
        let endpoint =
            build_short_idle_client_endpoint().expect("short-idle endpoint should build");

        let dummy_socket =
            std::net::UdpSocket::bind("127.0.0.1:0").expect("dummy UDP socket should bind");
        let dummy_addr = dummy_socket
            .local_addr()
            .expect("dummy UDP socket should have a local address");

        let elapsed = timeout(
            Duration::from_secs(2),
            connect_with_retry(
                &endpoint,
                dummy_addr,
                TEST_SERVER_NAME,
                TimeoutPolicy::RetryForever,
                &CancellationToken::new(),
            ),
        )
        .await;
        assert!(
            elapsed.is_err(),
            "RetryForever must keep looping on TimedOut, but the helper returned: {elapsed:?}"
        );
    }
}
