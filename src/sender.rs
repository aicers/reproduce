use std::{
    fs,
    net::SocketAddr,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::Error as AnyhowError;
use giganto_client::{
    RawEventKind,
    connection::client_handshake,
    frame::{RecvError, SendError, send_raw},
    ingest::{receive_ack_timestamp, send_record_header},
};
use quinn::{Connection, Endpoint, RecvStream, SendStream, TransportConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use thiserror::Error;
use tokio::task;
use tokio::time::sleep;
use tracing::{info, warn};

/// Limits the number of finish-ACK polling iterations before force-closing.
pub const CHANNEL_CLOSE_COUNT: u8 = 150;

/// Defines the sentinel payload sent to signal that a channel is done.
pub const CHANNEL_CLOSE_MESSAGE: &[u8; 12] = b"channel done";

/// Defines the sentinel timestamp used for channel-close messages and finish ACKs.
pub const CHANNEL_CLOSE_TIMESTAMP: i64 = -1;

/// Defines the minimum Giganto server version that this client is compatible with.
pub const REQUIRED_GIGANTO_VERSION: &str = "0.27.0-alpha.1";

/// Defines the keep-alive and reconnect interval in seconds.
pub const INTERVAL: u64 = 5;

/// Limits the maximum number of events to accumulate before flushing a batch.
pub const BATCH_SIZE: usize = 100;

#[derive(Debug, Error)]
pub enum SenderError {
    #[error("failed to connect Giganto")]
    Connect(#[source] quinn::ConnectError),

    #[error("Giganto connection failed")]
    Connection(#[source] quinn::ConnectionError),

    #[error("Giganto handshake failed")]
    Handshake(#[source] AnyhowError),

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

    #[error("{0:?}")]
    Send(#[source] SendError),

    #[error("receive ACK err: {0}")]
    ReceiveAck(RecvError),
}

impl SenderError {
    fn context(context: &'static str, source: impl Into<AnyhowError>) -> Self {
        Self::Context {
            context,
            source: source.into(),
        }
    }
}

/// Represents a QUIC/TLS connection to a Giganto ingest server, capable of sending
/// batched raw events and managing reconnection.
#[derive(Debug)]
pub struct GigantoSender {
    endpoint: Endpoint,
    server_addr: SocketAddr,
    name: String,
    conn: Connection,
    sender: SendStream,
    init_msg: bool,
    finish_checker: Arc<AtomicBool>,
}

impl GigantoSender {
    /// Creates a new `GigantoSender` by establishing a QUIC connection to the
    /// Giganto ingest server.
    ///
    /// Combines endpoint creation with the initial
    /// connection handshake and bidirectional stream setup. If the server is
    /// temporarily unreachable (`TimedOut`), retries indefinitely.
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
    ) -> std::result::Result<Self, SenderError> {
        let cert = cert.to_owned();
        let key = key.to_owned();
        let ca_certs = ca_certs.to_vec();
        let endpoint = task::spawn_blocking(move || create_endpoint(&cert, &key, &ca_certs))
            .await
            .map_err(|source| {
                SenderError::context("failed to join endpoint creation task", source)
            })??;
        let (conn, send, finish_checker) =
            connect_stream(&endpoint, server_addr, server_name).await?;
        info!("Connected to data store ingest server at {server_addr}");

        Ok(Self {
            endpoint,
            server_addr,
            name: server_name.to_string(),
            conn,
            sender: send,
            init_msg: true,
            finish_checker,
        })
    }

    /// Resets the header flag so that the next call to `ensure_header_sent`
    /// will write the record header again.
    pub fn reset_header(&mut self) {
        self.init_msg = true;
    }

    /// Sends the record header for `protocol` if it has not yet been sent on
    /// the current stream.
    ///
    /// After a successful send the internal flag is cleared so that subsequent
    /// calls are no-ops until the next reconnection.
    ///
    /// # Errors
    ///
    /// Returns an error if writing the header to the QUIC stream fails.
    pub async fn ensure_header_sent(
        &mut self,
        protocol: RawEventKind,
    ) -> std::result::Result<(), SenderError> {
        if self.init_msg {
            send_record_header(&mut self.sender, protocol)
                .await
                .map_err(SenderError::Send)?;
            self.init_msg = false;
        }
        Ok(())
    }

    /// Sends a batch of `(timestamp, serialized_event)` pairs to the Giganto
    /// server.
    ///
    /// # Errors
    ///
    /// Returns a `SendError` if serialization or writing to the stream fails.
    pub async fn send_batch(&mut self, events: &[(i64, Vec<u8>)]) -> Result<(), SendError> {
        let buf = bincode::serialize(&events)?;
        send_raw(&mut self.sender, &buf).await
    }

    /// Gracefully finishes the current stream by sending the channel-close
    /// sentinel and waiting for the server to acknowledge.
    ///
    /// If no ACK is received within roughly 15 seconds (150 iterations of
    /// 100 ms), the connection is closed anyway.
    ///
    /// # Errors
    ///
    /// Returns an error if the channel-close message cannot be sent or the
    /// stream cannot be finished.
    pub async fn finish(&mut self) -> std::result::Result<(), SenderError> {
        self.send_finish().await?;
        let mut force_finish_count = 0;
        loop {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if self.finish_checker.load(Ordering::SeqCst) {
                self.sender
                    .finish()
                    .map_err(|source| SenderError::context("failed to finish stream", source))?;
                self.conn.close(0u32.into(), b"log_done");
                self.endpoint.wait_idle().await;
                break;
            }

            force_finish_count += 1;
            if force_finish_count == CHANNEL_CLOSE_COUNT {
                break;
            }
        }
        info!("Data Store ended");
        Ok(())
    }

    /// Tears down the current QUIC stream and establishes a fresh one,
    /// performing the handshake again.
    ///
    /// On `TimedOut` the method retries indefinitely. After a successful
    /// reconnection `init_msg` is reset to `true` so that the next call to
    /// `ensure_header_sent` will write the record header.
    ///
    /// # Errors
    ///
    /// Returns an error if the handshake or stream opening fails.
    pub async fn reconnect(&mut self) -> std::result::Result<(), SenderError> {
        sleep(Duration::from_secs(2)).await;
        let (conn, send, finish_checker) =
            connect_stream(&self.endpoint, self.server_addr, &self.name).await?;
        self.conn = conn;
        self.sender = send;
        self.init_msg = true;
        self.finish_checker = finish_checker;
        Ok(())
    }

    /// Sends the channel-close sentinel message to signal the server that
    /// no more events will follow.
    async fn send_finish(&mut self) -> std::result::Result<(), SenderError> {
        let record_data = bincode::serialize(CHANNEL_CLOSE_MESSAGE)
            .map_err(|error| SenderError::Send(error.into()))?;
        let buf = vec![(CHANNEL_CLOSE_TIMESTAMP, record_data)];
        match self.send_batch(&buf).await {
            Err(SendError::WriteError(_)) => return Err(SenderError::SendFinish),
            Err(e) => return Err(SenderError::Send(e)),
            Ok(()) => {}
        }
        Ok(())
    }
}

/// Establishes a connected QUIC stream and starts the background ACK task.
async fn connect_stream(
    endpoint: &Endpoint,
    server_addr: SocketAddr,
    server_name: &str,
) -> std::result::Result<(Connection, SendStream, Arc<AtomicBool>), SenderError> {
    let conn = connect_with_retry(endpoint, server_addr, server_name).await?;
    client_handshake(&conn, REQUIRED_GIGANTO_VERSION)
        .await
        .map_err(|source| SenderError::Handshake(source.into()))?;

    let (send, recv) = conn
        .open_bi()
        .await
        .map_err(|source| SenderError::context("failed to open stream to Giganto", source))?;
    let finish_checker_send = Arc::new(AtomicBool::new(false));
    let finish_checker_recv = Arc::clone(&finish_checker_send);

    tokio::spawn(async move {
        let _ = recv_ack(recv, finish_checker_recv).await;
    });

    Ok((conn, send, finish_checker_send))
}

/// Connects to the server, retrying on timeout to preserve the legacy behavior.
async fn connect_with_retry(
    endpoint: &Endpoint,
    server_addr: SocketAddr,
    server_name: &str,
) -> std::result::Result<Connection, SenderError> {
    loop {
        match endpoint
            .connect(server_addr, server_name)
            .map_err(SenderError::Connect)?
            .await
        {
            Ok(conn) => return Ok(conn),
            Err(quinn::ConnectionError::TimedOut) => {
                info!("Server timeout, reconnecting...");
                sleep(Duration::from_secs(INTERVAL)).await;
            }
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
    let client_crypto = rustls::ClientConfig::builder()
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

/// Receives acknowledgement timestamps from the server and sets the
/// finish-checker flag when the channel-close sentinel is echoed back.
async fn recv_ack(
    mut recv: RecvStream,
    finish_checker: Arc<AtomicBool>,
) -> std::result::Result<(), SenderError> {
    loop {
        match receive_ack_timestamp(&mut recv).await {
            Ok(timestamp) => {
                if timestamp == CHANNEL_CLOSE_TIMESTAMP {
                    finish_checker.store(true, Ordering::SeqCst);
                    info!("Finish ACK: {timestamp}");
                } else {
                    info!("ACK: {timestamp}");
                }
            }
            Err(RecvError::ReadError(quinn::ReadExactError::FinishedEarly(_))) => {
                warn!("Finished early");
                break;
            }
            Err(e) => return Err(SenderError::ReceiveAck(e)),
        }
    }
    Ok(())
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
    use quinn::{Connection, RecvStream, SendStream};
    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose};
    use tempfile::tempdir;
    use tokio::time::{Duration, timeout};

    use super::*;

    const TEST_ROOT_PEM: &str = "tests/root.pem";
    const TEST_CERT_PEM: &str = "tests/cert.pem";
    const TEST_KEY_PEM: &str = "tests/key.pem";
    const TEST_SERVER_NAME: &str = "localhost";
    const TEST_TIMEOUT: Duration = Duration::from_secs(5);

    fn fixture_path(relative: &str) -> String {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join(relative)
            .to_string_lossy()
            .into_owned()
    }

    fn load_cert_chain(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
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

    fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
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

    fn build_server_endpoint() -> Result<(Endpoint, SocketAddr)> {
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
        let endpoint = Endpoint::server(server_config, bind_addr)
            .context("test server endpoint should bind")?;
        let addr = endpoint
            .local_addr()
            .context("test server endpoint should have a local address")?;
        Ok((endpoint, addr))
    }

    struct ServerSession {
        server_endpoint: Endpoint,
        connection: Connection,
    }

    async fn connect_stream_sender() -> Result<(GigantoSender, ServerSession)> {
        let (server_endpoint, server_addr) = build_server_endpoint()?;
        let cert = fixture_path(TEST_CERT_PEM);
        let key = fixture_path(TEST_KEY_PEM);
        let root = fixture_path(TEST_ROOT_PEM);
        let roots = [root];
        let client_endpoint = create_endpoint(&cert, &key, &roots)?;

        let connect = client_endpoint
            .connect(server_addr, TEST_SERVER_NAME)
            .context("test sender should start connecting")?;
        let (client_conn, server_conn) = tokio::join!(
            async {
                connect
                    .await
                    .context("test sender should connect to the test server")
            },
            async {
                let incoming = timeout(TEST_TIMEOUT, server_endpoint.accept())
                    .await
                    .context("test server should accept a sender connection in time")?
                    .context("test server endpoint should stay open while accepting")?;
                incoming
                    .await
                    .context("sender connection should complete QUIC setup")
            },
        );
        let client_conn = client_conn?;
        let server_conn = server_conn?;

        let (client_send, client_recv) = client_conn
            .open_bi()
            .await
            .context("test sender should open a data stream")?;

        let finish_checker_send = Arc::new(AtomicBool::new(false));
        let finish_checker_recv = Arc::clone(&finish_checker_send);
        tokio::spawn(async move {
            let _ = recv_ack(client_recv, finish_checker_recv).await;
        });

        Ok((
            GigantoSender {
                endpoint: client_endpoint,
                server_addr,
                name: TEST_SERVER_NAME.to_string(),
                conn: client_conn,
                sender: client_send,
                init_msg: true,
                finish_checker: finish_checker_send,
            },
            ServerSession {
                server_endpoint,
                connection: server_conn,
            },
        ))
    }

    async fn accept_server_stream(connection: &Connection) -> Result<(SendStream, RecvStream)> {
        timeout(TEST_TIMEOUT, connection.accept_bi())
            .await
            .context("test server should accept the sender data stream in time")?
            .context("server should accept the sender data stream")
    }

    struct AckChannel {
        _server_endpoint: Endpoint,
        _client_endpoint: Endpoint,
        server_send: SendStream,
        client_recv: RecvStream,
    }

    async fn open_ack_channel() -> Result<AckChannel> {
        let (server_endpoint, server_addr) = build_server_endpoint()?;
        let cert = fixture_path(TEST_CERT_PEM);
        let key = fixture_path(TEST_KEY_PEM);
        let root = fixture_path(TEST_ROOT_PEM);
        let client_endpoint = create_endpoint(&cert, &key, &[root])?;

        let connect = client_endpoint
            .connect(server_addr, TEST_SERVER_NAME)
            .context("test client should start connecting")?;
        let (client_conn, server_conn) = tokio::join!(
            async {
                connect
                    .await
                    .context("test client should connect to server")
            },
            async {
                let incoming = timeout(TEST_TIMEOUT, server_endpoint.accept())
                    .await
                    .context("test server should accept a raw channel in time")?
                    .context("test server endpoint should stay open while accepting")?;
                incoming
                    .await
                    .context("raw test channel should complete QUIC setup")
            },
        );
        let client_conn = client_conn?;
        let server_conn = server_conn?;

        let (mut client_send, client_recv) = client_conn
            .open_bi()
            .await
            .context("test client should open a raw stream")?;
        client_send
            .finish()
            .context("test client raw send stream should finish")?;
        let (server_send, mut server_recv) = server_conn
            .accept_bi()
            .await
            .context("test server should accept the raw stream")?;
        let _ = timeout(TEST_TIMEOUT, server_recv.read_to_end(usize::MAX))
            .await
            .context("test server should observe the raw stream finish")?
            .context("test server should drain the raw stream")?;

        Ok(AckChannel {
            _server_endpoint: server_endpoint,
            _client_endpoint: client_endpoint,
            server_send,
            client_recv,
        })
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
    fn to_root_cert_loads_bundled_pem_with_multiple_certificates() {
        let root_pem = fs::read(fixture_path(TEST_ROOT_PEM))
            .expect("fixture root certificate should be readable");
        let dir = tempdir().expect("tempdir should be created");
        let bundled_path = dir.path().join("bundled-roots.pem");
        let mut bundled = root_pem.clone();
        bundled.extend_from_slice(&root_pem);
        fs::write(&bundled_path, &bundled).expect("bundled PEM fixture should be written");

        let store = to_root_cert(&[bundled_path.to_string_lossy().into_owned()])
            .expect("bundled PEM with multiple certificates should load");
        assert_eq!(store.len(), 2);
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
    async fn ensure_header_sent_writes_once_until_reset() {
        let (mut sender, session) = connect_stream_sender()
            .await
            .expect("sender should connect to the test server");

        sender
            .ensure_header_sent(RawEventKind::Dns)
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
            .ensure_header_sent(RawEventKind::Dns)
            .await
            .expect("second header send should be a no-op");
        let mut duplicate_header = [0_u8; std::mem::size_of::<u32>()];
        assert!(
            timeout(
                Duration::from_millis(100),
                receive_record_header(&mut server_recv, &mut duplicate_header),
            )
            .await
            .is_err(),
            "header should not be written twice without reset_header()",
        );

        sender.reset_header();
        sender
            .ensure_header_sent(RawEventKind::Dns)
            .await
            .expect("header send after reset should succeed");
        receive_record_header(&mut server_recv, &mut header)
            .await
            .expect("server should receive the reset record header");
        assert_eq!(header, u32::from(RawEventKind::Dns).to_le_bytes());
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

        let finish_handle = tokio::spawn(async move { sender.finish().await });
        let (mut server_send, mut server_recv) = accept_server_stream(&session.connection)
            .await
            .expect("server should observe the sender stream after finish starts");

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
    }

    #[tokio::test]
    async fn send_finish_returns_error_when_stream_write_fails() {
        let (mut sender, session) = connect_stream_sender()
            .await
            .expect("sender should connect to the test server");

        session.connection.close(0u32.into(), b"send-finish-error");
        tokio::time::sleep(Duration::from_millis(100)).await;

        let err = sender
            .send_finish()
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

        let (sender_result, server_result) = tokio::join!(
            GigantoSender::new(&cert, &key, &roots, server_addr, TEST_SERVER_NAME),
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
        let SenderError::Handshake(handshake_source) = &err else {
            panic!("sender creation should fail with a handshake error, got {err:?}");
        };
        let handshake_err = handshake_source
            .downcast_ref::<HandshakeError>()
            .expect("sender creation error should preserve the handshake error type");
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
        let (server_endpoint, server_addr) =
            build_server_endpoint().expect("test server endpoint should be created");
        let cert = fixture_path(TEST_CERT_PEM);
        let key = fixture_path(TEST_KEY_PEM);
        let root = fixture_path(TEST_ROOT_PEM);
        let roots = [root];

        let server_task = tokio::spawn(async move {
            let incoming = timeout(TEST_TIMEOUT, server_endpoint.accept())
                .await
                .context("test server should accept a sender connection in time")?
                .context("test server endpoint should stay open while accepting")?;
            let connection = incoming
                .await
                .context("sender connection should complete QUIC setup")?;
            server_handshake(&connection, REQUIRED_GIGANTO_VERSION).await?;
            Ok::<_, anyhow::Error>(connection)
        });

        let mut sender = GigantoSender::new(&cert, &key, &roots, server_addr, TEST_SERVER_NAME)
            .await
            .expect("compatible server should accept sender creation");
        let connection = server_task
            .await
            .expect("server task should join cleanly")
            .expect("server handshake should succeed");

        assert_eq!(sender.server_addr, server_addr);
        assert_eq!(sender.name, TEST_SERVER_NAME);
        assert!(sender.init_msg);

        sender
            .ensure_header_sent(RawEventKind::Dns)
            .await
            .expect("new sender should write a header on its stream");
        let (_server_send, mut server_recv) = accept_server_stream(&connection)
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
        let accept_timeout = TEST_TIMEOUT + Duration::from_secs(3);

        let (reconnect_result, server_result) = tokio::join!(sender.reconnect(), async {
            let incoming = timeout(accept_timeout, session.server_endpoint.accept())
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
        let SenderError::Handshake(handshake_source) = &err else {
            panic!("reconnect should fail with a handshake error, got {err:?}");
        };
        let handshake_err = handshake_source
            .downcast_ref::<HandshakeError>()
            .expect("reconnect error should preserve the handshake error type");
        assert!(
            matches!(
                handshake_err,
                HandshakeError::IncompatibleProtocol(_) | HandshakeError::ReadError(_)
            ),
            "unexpected reconnect handshake error: {handshake_err:?}"
        );
    }

    #[tokio::test]
    async fn reconnect_reestablishes_the_stream_and_resets_header_state() {
        let (mut sender, session) = connect_stream_sender()
            .await
            .expect("sender should connect to the test server");

        sender
            .ensure_header_sent(RawEventKind::Dns)
            .await
            .expect("initial sender should write a header");
        let (_old_send, mut old_recv) = accept_server_stream(&session.connection)
            .await
            .expect("server should accept the original sender stream");
        let mut header = [0_u8; std::mem::size_of::<u32>()];
        receive_record_header(&mut old_recv, &mut header)
            .await
            .expect("server should receive the original header");
        assert_eq!(header, u32::from(RawEventKind::Dns).to_le_bytes());
        assert!(!sender.init_msg);

        let accept_timeout = TEST_TIMEOUT + Duration::from_secs(3);
        let server_task = tokio::spawn(async move {
            let incoming = timeout(accept_timeout, session.server_endpoint.accept())
                .await
                .context("test server should accept a reconnect in time")?
                .context("test server endpoint should stay open while accepting")?;
            let connection = incoming
                .await
                .context("sender reconnect should complete QUIC setup")?;
            server_handshake(&connection, REQUIRED_GIGANTO_VERSION).await?;
            Ok::<_, anyhow::Error>(connection)
        });

        sender
            .reconnect()
            .await
            .expect("compatible server should allow reconnect");
        assert!(sender.init_msg);

        let connection = server_task
            .await
            .expect("server reconnect task should join cleanly")
            .expect("server reconnect handshake should succeed");

        sender
            .ensure_header_sent(RawEventKind::Dns)
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

    #[tokio::test]
    async fn recv_ack_sets_finish_checker_on_close_ack() {
        let mut channel = open_ack_channel()
            .await
            .expect("raw ACK channel should be established");
        let finish_checker = Arc::new(AtomicBool::new(false));
        let recv_handle = tokio::spawn(recv_ack(channel.client_recv, finish_checker.clone()));

        channel
            .server_send
            .write_all(&CHANNEL_CLOSE_TIMESTAMP.to_be_bytes())
            .await
            .expect("server should send the close ACK timestamp");
        channel
            .server_send
            .finish()
            .expect("server should finish the ACK stream");

        recv_handle
            .await
            .expect("recv_ack task should join cleanly")
            .expect("recv_ack should treat a clean close as success");
        assert!(
            finish_checker.load(Ordering::SeqCst),
            "close ACK should set the finish checker flag",
        );
    }

    #[tokio::test]
    async fn recv_ack_leaves_flag_clear_for_regular_ack() {
        let mut channel = open_ack_channel()
            .await
            .expect("raw ACK channel should be established");
        let finish_checker = Arc::new(AtomicBool::new(false));
        let recv_handle = tokio::spawn(recv_ack(channel.client_recv, finish_checker.clone()));

        channel
            .server_send
            .write_all(&123_i64.to_be_bytes())
            .await
            .expect("server should send a regular ACK timestamp");
        channel
            .server_send
            .finish()
            .expect("server should finish the ACK stream");

        recv_handle
            .await
            .expect("recv_ack task should join cleanly")
            .expect("recv_ack should return success after stream close");
        assert!(
            !finish_checker.load(Ordering::SeqCst),
            "non-close ACKs must not set the finish checker flag",
        );
    }

    // ---------------------------------------------------------------
    // Bootroot-style certificate chain helpers and integration tests
    // ---------------------------------------------------------------

    /// Generated Bootroot-style PKI material: root CA -> intermediate CA -> leaf.
    #[allow(clippy::struct_field_names)]
    struct BootrootPki {
        root_ca_pem: String,
        intermediate_ca_pem: String,
        leaf_cert_pem: String,
        leaf_key_pem: String,
    }

    /// Generates a three-level certificate chain modelling a Bootroot deployment:
    /// `leaf <- intermediate <- root`.
    ///
    /// The leaf certificate has `localhost` as the subject and SAN so that
    /// it can be used for both server and client identity in local tests.
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

        // Leaf (localhost)
        let mut leaf_params = CertificateParams::new(vec!["localhost".to_string()])
            .expect("leaf params should be valid");
        leaf_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "localhost");
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf_params.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let leaf_key = KeyPair::generate().expect("leaf key should generate");
        let inter_issuer = Issuer::from_ca_cert_der(inter_cert.der(), &inter_key)
            .expect("intermediate issuer should be constructible");
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &inter_issuer)
            .expect("leaf should be signed by intermediate");

        BootrootPki {
            root_ca_pem: root_cert.pem(),
            intermediate_ca_pem: inter_cert.pem(),
            leaf_cert_pem: leaf_cert.pem(),
            leaf_key_pem: leaf_key.serialize_pem(),
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
    fn to_root_cert_regression_rejects_first_pem_only_if_both_needed() {
        let pki = generate_bootroot_pki();
        let dir = tempdir().expect("tempdir should be created");

        // Write only the intermediate (first cert of a bundle) as the sole CA.
        // A leaf signed by the intermediate cannot be validated without the
        // root in the store, so the store must contain both.
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
    async fn create_endpoint_with_bootroot_bundle() {
        let pki = generate_bootroot_pki();
        let dir = tempdir().expect("tempdir should be created");

        // leaf-chain.pem = leaf + intermediate (for client cert chain)
        let chain = format!("{}{}", pki.leaf_cert_pem, pki.intermediate_ca_pem);
        let cert_path = write_pem(dir.path(), "leaf-chain.pem", &chain);
        let key_path = write_pem(dir.path(), "leaf-key.pem", &pki.leaf_key_pem);
        let bundle = format!("{}{}", pki.intermediate_ca_pem, pki.root_ca_pem);
        let ca_path = write_pem(dir.path(), "ca-bundle.pem", &bundle);

        let endpoint = create_endpoint(&cert_path, &key_path, &[ca_path])
            .expect("Bootroot cert/key/CA bundle should create endpoint");
        drop(endpoint);
    }

    #[tokio::test]
    async fn create_endpoint_with_split_ca_files() {
        let pki = generate_bootroot_pki();
        let dir = tempdir().expect("tempdir should be created");

        let chain = format!("{}{}", pki.leaf_cert_pem, pki.intermediate_ca_pem);
        let cert_path = write_pem(dir.path(), "leaf-chain.pem", &chain);
        let key_path = write_pem(dir.path(), "leaf-key.pem", &pki.leaf_key_pem);
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
        let chain_pem = format!("{}{}", pki.leaf_cert_pem, pki.intermediate_ca_pem);
        let chain_bytes = chain_pem.as_bytes();
        let cert_chain: Vec<CertificateDer> = rustls_pemfile::certs(&mut &*chain_bytes)
            .collect::<std::result::Result<_, _>>()
            .context("server cert chain PEM should parse")?;

        let key_bytes = pki.leaf_key_pem.as_bytes();
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

        let client_verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(client_roots))
            .build()
            .context("client verifier should build")?;

        let server_crypto = rustls::ServerConfig::builder()
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
        let chain = format!("{}{}", pki.leaf_cert_pem, pki.intermediate_ca_pem);
        let cert_path = write_pem(dir.path(), "client-chain.pem", &chain);
        let key_path = write_pem(dir.path(), "client-key.pem", &pki.leaf_key_pem);
        let bundle = format!("{}{}", pki.intermediate_ca_pem, pki.root_ca_pem);
        let ca_path = write_pem(dir.path(), "ca-bundle.pem", &bundle);

        let client_endpoint = create_endpoint(&cert_path, &key_path, &[ca_path])
            .expect("client endpoint should be created");

        let connect = client_endpoint
            .connect(server_addr, "localhost")
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
        // Server presents ONLY the leaf cert (no intermediate in chain).
        let cert_bytes = pki.leaf_cert_pem.as_bytes();
        let cert_chain: Vec<CertificateDer> = rustls_pemfile::certs(&mut &*cert_bytes)
            .collect::<std::result::Result<_, _>>()
            .context("leaf cert PEM should parse")?;

        let key_bytes = pki.leaf_key_pem.as_bytes();
        let private_key = rustls_pemfile::private_key(&mut &*key_bytes)
            .context("leaf key PEM should parse")?
            .context("leaf key PEM should contain a key")?;

        let server_crypto = rustls::ServerConfig::builder()
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
        let cert_path = write_pem(dir.path(), "client-cert.pem", &pki.leaf_cert_pem);
        let key_path = write_pem(dir.path(), "client-key.pem", &pki.leaf_key_pem);
        let ca_path = write_pem(dir.path(), "root-only.pem", &pki.root_ca_pem);

        let client_endpoint = create_endpoint(&cert_path, &key_path, &[ca_path])
            .expect("client endpoint should be created");

        let connect = client_endpoint
            .connect(server_addr, "localhost")
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
        let cert_path = write_pem(dir.path(), "client-cert.pem", &pki.leaf_cert_pem);
        let key_path = write_pem(dir.path(), "client-key.pem", &pki.leaf_key_pem);
        let bundle = format!("{}{}", pki.intermediate_ca_pem, pki.root_ca_pem);
        let ca_path = write_pem(dir.path(), "ca-bundle.pem", &bundle);

        let client_endpoint = create_endpoint(&cert_path, &key_path, &[ca_path])
            .expect("client endpoint should be created");

        let connect = client_endpoint
            .connect(server_addr, "localhost")
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

        let chain = format!("{}{}", pki.leaf_cert_pem, pki.intermediate_ca_pem);
        let cert_path = write_pem(dir.path(), "client-chain.pem", &chain);
        let key_path = write_pem(dir.path(), "client-key.pem", &pki.leaf_key_pem);
        let root_path = write_pem(dir.path(), "root.pem", &pki.root_ca_pem);
        let inter_path = write_pem(dir.path(), "intermediate.pem", &pki.intermediate_ca_pem);

        let client_endpoint = create_endpoint(&cert_path, &key_path, &[root_path, inter_path])
            .expect("client endpoint should be created");

        let connect = client_endpoint
            .connect(server_addr, "localhost")
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
}
