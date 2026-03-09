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

use anyhow::{Context, Result, bail};
use giganto_client::{
    RawEventKind,
    connection::client_handshake,
    frame::{RecvError, SendError, send_raw},
    ingest::{receive_ack_timestamp, send_record_header},
};
use quinn::{Connection, Endpoint, RecvStream, SendStream, TransportConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::time::sleep;
use tracing::{info, warn};

/// Number of iterations to wait for a finish ACK before force-closing.
pub const CHANNEL_CLOSE_COUNT: u8 = 150;

/// Sentinel payload sent to signal that a channel is done.
pub const CHANNEL_CLOSE_MESSAGE: &[u8; 12] = b"channel done";

/// Sentinel timestamp used for channel-close messages and finish ACKs.
pub const CHANNEL_CLOSE_TIMESTAMP: i64 = -1;

/// Minimum Giganto server version that this client is compatible with.
pub const REQUIRED_GIGANTO_VERSION: &str = "0.26.1";

/// Keep-alive and reconnect interval in seconds.
pub const INTERVAL: u64 = 5;

/// Maximum number of events to accumulate before flushing a batch.
pub const BATCH_SIZE: usize = 100;

/// A QUIC/TLS connection to a Giganto ingest server, capable of sending
/// batched raw events and managing reconnection.
#[derive(Debug)]
pub struct GigantoSender {
    endpoint: Endpoint,
    server_addr: SocketAddr,
    name: String,
    kind: String,
    conn: Connection,
    sender: SendStream,
    init_msg: bool,
    finish_checker: Arc<AtomicBool>,
}

impl GigantoSender {
    /// Creates a new `GigantoSender` by establishing a QUIC connection to the
    /// Giganto ingest server.
    ///
    /// Combines endpoint creation (`create_endpoint`) with the initial
    /// connection handshake and bidirectional stream setup. If the server is
    /// temporarily unreachable (`TimedOut`), retries indefinitely.
    ///
    /// # Errors
    ///
    /// Returns an error if the TLS certificates are invalid, the endpoint
    /// cannot be created, or the handshake with the server fails.
    ///
    /// # Panics
    ///
    /// Panics on a `ConnectionError` variant other than `TimedOut`.
    pub async fn new(
        cert: &str,
        key: &str,
        ca_certs: &[String],
        server_addr: SocketAddr,
        server_name: &str,
        kind: &str,
    ) -> Result<Self> {
        let endpoint = create_endpoint(cert, key, ca_certs)?;

        loop {
            let conn = match endpoint
                .connect(server_addr, server_name)
                .context("failed to connect Giganto")?
                .await
            {
                Ok(r) => {
                    info!("Connected to data store ingest server at {server_addr}");
                    r
                }
                Err(quinn::ConnectionError::TimedOut) => {
                    info!("Server timeout, reconnecting...");
                    sleep(Duration::from_secs(INTERVAL)).await;
                    continue;
                }
                Err(e) => panic!("{e}"),
            };

            client_handshake(&conn, REQUIRED_GIGANTO_VERSION).await?;

            let (send, recv) = conn
                .open_bi()
                .await
                .context("failed to open stream to Giganto")?;

            let finish_checker_send = Arc::new(AtomicBool::new(false));
            let finish_checker_recv = finish_checker_send.clone();

            tokio::spawn(async move { recv_ack(recv, finish_checker_recv).await });

            return Ok(Self {
                endpoint,
                server_addr,
                name: server_name.to_string(),
                kind: kind.to_string(),
                conn,
                sender: send,
                init_msg: true,
                finish_checker: finish_checker_send,
            });
        }
    }

    /// Returns the kind identifier for this sender (e.g. the data source
    /// kind such as `"zeek"` or `"sysmon"`).
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
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
    pub async fn ensure_header_sent(&mut self, protocol: RawEventKind) -> Result<()> {
        if self.init_msg {
            send_record_header(&mut self.sender, protocol).await?;
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
    pub async fn finish(&mut self) -> Result<()> {
        self.send_finish().await?;
        let mut force_finish_count = 0;
        loop {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if self.finish_checker.load(Ordering::SeqCst) {
                self.sender.finish().context("failed to finish stream")?;
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
    ///
    /// # Panics
    ///
    /// Panics on a `ConnectionError` variant other than `TimedOut`.
    pub async fn reconnect(&mut self) -> Result<()> {
        loop {
            sleep(Duration::from_secs(2)).await;
            let conn = match self
                .endpoint
                .connect(self.server_addr, &self.name)
                .context("failed to connect Giganto")?
                .await
            {
                Ok(r) => r,
                Err(quinn::ConnectionError::TimedOut) => {
                    info!("Server timeout, reconnecting...");
                    sleep(Duration::from_secs(INTERVAL)).await;
                    continue;
                }
                Err(e) => panic!("{e}"),
            };

            client_handshake(&conn, REQUIRED_GIGANTO_VERSION).await?;

            let (send, recv) = conn
                .open_bi()
                .await
                .context("failed to open stream to Giganto")?;
            let finish_checker_send = Arc::new(AtomicBool::new(false));
            let finish_checker_recv = finish_checker_send.clone();

            tokio::spawn(async move { recv_ack(recv, finish_checker_recv).await });

            self.conn = conn;
            self.sender = send;
            self.init_msg = true;
            self.finish_checker = finish_checker_send;

            return Ok(());
        }
    }

    /// Sends the channel-close sentinel message to signal the server that
    /// no more events will follow.
    async fn send_finish(&mut self) -> Result<()> {
        let record_data = bincode::serialize(CHANNEL_CLOSE_MESSAGE)?;
        let buf = vec![(CHANNEL_CLOSE_TIMESTAMP, record_data)];
        match self.send_batch(&buf).await {
            Err(SendError::WriteError(_)) => {
                bail!("failed to send channel done message");
            }
            Err(e) => {
                bail!("{e:?}");
            }
            Ok(()) => {}
        }
        Ok(())
    }
}

/// Creates a QUIC client `Endpoint` configured with the given TLS
/// certificate, private key, and CA root certificates.
///
/// # Errors
///
/// Returns an error if the certificate or key files cannot be read, parsed,
/// or if the TLS configuration is invalid.
///
/// # Panics
///
/// Panics if the PEM-encoded private key or certificate is malformed, or if
/// the QUIC client configuration cannot be built.
pub fn create_endpoint(cert: &str, key: &str, ca_certs: &[String]) -> Result<Endpoint> {
    let Ok((cert_pem, key_pem)) = fs::read(cert).and_then(|x| Ok((x, fs::read(key)?))) else {
        bail!("failed to read (cert, key) file. cert_path:{cert}, key_path:{key}");
    };

    let pv_key = if Path::new(key).extension().is_some_and(|x| x == "der") {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pem))
    } else {
        rustls_pemfile::private_key(&mut &*key_pem)
            .context("malformed PKCS #1 private key")?
            .context("no private keys found")?
    };

    let cert_chain = if Path::new(cert).extension().is_some_and(|x| x == "der") {
        vec![CertificateDer::from(cert_pem)]
    } else {
        rustls_pemfile::certs(&mut &*cert_pem)
            .collect::<Result<_, _>>()
            .context("invalid PEM-encoded certificate")?
    };

    let server_root = to_root_cert(ca_certs)?;

    let client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(server_root)
        .with_client_auth_cert(cert_chain, pv_key)
        .context("invalid client certificate or private key")?;

    let mut transport = TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(INTERVAL)));

    let mut client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
            .context("failed to build QUIC client config")?,
    ));
    client_config.transport_config(Arc::new(transport));

    // "[::]:0" is a hardcoded valid IPv6 any-address with ephemeral port
    let mut endpoint = quinn::Endpoint::client("[::]:0".parse().expect("[::]:0 is always valid"))
        .context("failed to create QUIC endpoint")?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

/// Builds a `RootCertStore` from a list of PEM-encoded CA certificate file
/// paths.
///
/// # Errors
///
/// Returns an error if any certificate file cannot be read or contains
/// invalid PEM data.
pub fn to_root_cert(ca_certs_paths: &[String]) -> Result<rustls::RootCertStore> {
    let mut ca_certs_files = Vec::new();

    for ca_cert in ca_certs_paths {
        let file = fs::read(ca_cert)
            .with_context(|| format!("failed to read root certificate file: {ca_cert}"))?;

        ca_certs_files.push(file);
    }
    let mut root_cert = rustls::RootCertStore::empty();
    for file in ca_certs_files {
        let root_certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut &*file)
            .collect::<Result<_, _>>()
            .context("invalid PEM-encoded certificate")?;
        if let Some(cert) = root_certs.first() {
            root_cert
                .add(cert.to_owned())
                .context("failed to add root cert")?;
        }
    }

    Ok(root_cert)
}

/// Receives acknowledgement timestamps from the server and sets the
/// finish-checker flag when the channel-close sentinel is echoed back.
async fn recv_ack(mut recv: RecvStream, finish_checker: Arc<AtomicBool>) -> Result<()> {
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
            Err(e) => bail!("receive ACK err: {e}"),
        }
    }
    Ok(())
}

/// Applies timestamp deduplication by incrementing the offset for consecutive
/// identical timestamps.
///
/// Returns the deduplicated timestamp (original + offset). When a new
/// timestamp is encountered the reference is updated and the offset resets to
/// 0. For identical consecutive timestamps the offset increments by 1 for
/// each occurrence.
pub fn apply_timestamp_dedup(
    current_timestamp: i64,
    reference_timestamp: &mut Option<i64>,
    timestamp_offset: &mut i64,
) -> i64 {
    if let Some(ref_ts) = *reference_timestamp {
        if current_timestamp == ref_ts {
            // Same timestamp, increment offset
            *timestamp_offset += 1;
        } else {
            // Different timestamp, update reference and reset offset
            *reference_timestamp = Some(current_timestamp);
            *timestamp_offset = 0;
        }
    } else {
        // First event, set reference timestamp
        *reference_timestamp = Some(current_timestamp);
    }
    current_timestamp + *timestamp_offset
}
