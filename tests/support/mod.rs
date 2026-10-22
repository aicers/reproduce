//! Helpers shared by the remote-mode tests: an rcgen PKI, a mock Central
//! Manager serving review-protocol, client TLS files, and log capture.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use quinn::Endpoint;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use reproduce::manager::TlsFiles;
use review_protocol::AgentInfo;
use review_protocol::server;
use review_protocol::types::Status;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tempfile::TempDir;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{Instant, sleep};

pub const SERVER_NAME: &str = "localhost";

/// The versions `REview` 0.61.0 accepts.
pub const VERSION_REQ: &str = ">=0.48.0";
pub const HIGHEST_PROTOCOL_VERSION: &str = "0.49.0";

#[allow(dead_code)]
pub const WAIT: Duration = Duration::from_secs(10);

/// A CA that signs the mock's certificate and every client certificate.
pub struct Pki {
    pub ca: String,
    pub issuer: Issuer<'static, KeyPair>,
    pub server: Identity,
}

/// A certificate and its private key, PEM-encoded.
#[derive(Clone)]
pub struct Identity {
    pub cert: String,
    pub key: String,
}

impl Identity {
    #[allow(dead_code)]
    pub fn der(&self) -> CertificateDer<'static> {
        rustls_pemfile::certs(&mut self.cert.as_bytes())
            .next()
            .expect("a certificate")
            .expect("a valid certificate")
    }
}

impl Pki {
    pub fn new() -> Result<Self> {
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Manager Test CA");
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let key = KeyPair::generate()?;
        let ca = params.self_signed(&key)?.pem();
        let issuer = Issuer::new(params, key);
        let server = issue(&issuer, SERVER_NAME, ExtendedKeyUsagePurpose::ServerAuth)?;
        Ok(Self { ca, issuer, server })
    }

    pub fn client(&self) -> Result<Identity> {
        issue(
            &self.issuer,
            "reproduce.test",
            ExtendedKeyUsagePurpose::ClientAuth,
        )
    }
}

pub fn issue(
    issuer: &Issuer<'static, KeyPair>,
    name: &str,
    usage: ExtendedKeyUsagePurpose,
) -> Result<Identity> {
    let mut params = CertificateParams::new(vec![name.to_string()])?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![usage];
    let key = KeyPair::generate()?;
    let cert = params.signed_by(&key, issuer)?;
    Ok(Identity {
        cert: cert.pem(),
        key: key.serialize_pem(),
    })
}

pub fn server_config(pki: &Pki) -> Result<quinn::ServerConfig> {
    server_config_trusting(&pki.server, &pki.ca)
}

/// Builds a server configuration presenting `server` and verifying client
/// certificates against `client_ca`, with the ring provider.
pub fn server_config_trusting(server: &Identity, client_ca: &str) -> Result<quinn::ServerConfig> {
    let certs = rustls_pemfile::certs(&mut server.cert.as_bytes())
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let key: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut server.key.as_bytes())?.context("a key")?;
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut client_ca.as_bytes()) {
        roots.add(cert?)?;
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        provider.clone(),
    )
    .build()?;
    let crypto = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(crypto)?,
    )))
}

/// A handshake the mock accepted.
#[allow(dead_code)]
pub struct Handshake {
    pub info: AgentInfo,
    pub cert: CertificateDer<'static>,
}

pub struct State {
    /// The stored configuration; `None` answers "config unavailable".
    pub config: Mutex<Option<String>>,
    pub delay: Mutex<Duration>,
    pub version_req: Mutex<String>,
    /// Connections that completed TLS, whether or not their handshake was
    /// accepted.
    pub attempts: AtomicUsize,
    pub handshakes: Mutex<Vec<Handshake>>,
    pub get_configs: AtomicUsize,
    /// The connection of the last accepted handshake.
    pub connection: Mutex<Option<quinn::Connection>>,
}

/// A mock Central Manager.
pub struct Mock {
    pub addr: SocketAddr,
    pub server_config: quinn::ServerConfig,
    pub state: Arc<State>,
    pub running: Option<(Endpoint, JoinHandle<()>)>,
}

impl Mock {
    pub fn start(pki: &Pki) -> Result<Self> {
        let server_config = server_config(pki)?;
        let state = Arc::new(State {
            config: Mutex::new(None),
            delay: Mutex::new(Duration::ZERO),
            version_req: Mutex::new(VERSION_REQ.to_string()),
            attempts: AtomicUsize::new(0),
            handshakes: Mutex::new(Vec::new()),
            get_configs: AtomicUsize::new(0),
            connection: Mutex::new(None),
        });
        let mut mock = Self {
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            server_config,
            state,
            running: None,
        };
        mock.restart()?;
        Ok(mock)
    }

    /// Starts serving again on the same address after [`Mock::stop`].
    pub fn restart(&mut self) -> Result<()> {
        let endpoint = Endpoint::server(self.server_config.clone(), self.addr)?;
        self.addr = endpoint.local_addr()?;
        let task = tokio::spawn(accept(endpoint.clone(), self.state.clone()));
        self.running = Some((endpoint, task));
        Ok(())
    }

    /// Closes every connection and stops listening.
    #[allow(dead_code)]
    pub async fn stop(&mut self) {
        if let Some((endpoint, task)) = self.running.take() {
            task.abort();
            let _ = task.await;
            self.state.connection.lock().expect("lock").take();
            endpoint.close(0u32.into(), b"stopped");
            endpoint.wait_idle().await;
        }
    }

    pub fn set_config(&self, config: Option<&str>) {
        *self.state.config.lock().expect("lock") = config.map(str::to_string);
    }

    #[allow(dead_code)]
    pub fn set_delay(&self, delay: Duration) {
        *self.state.delay.lock().expect("lock") = delay;
    }

    #[allow(dead_code)]
    pub fn set_version_req(&self, version_req: &str) {
        *self.state.version_req.lock().expect("lock") = version_req.to_string();
    }

    #[allow(dead_code)]
    pub fn attempts(&self) -> usize {
        self.state.attempts.load(Ordering::SeqCst)
    }

    #[allow(dead_code)]
    pub fn get_configs(&self) -> usize {
        self.state.get_configs.load(Ordering::SeqCst)
    }

    #[allow(dead_code)]
    pub fn handshakes(&self) -> usize {
        self.state.handshakes.lock().expect("lock").len()
    }

    #[allow(dead_code)]
    pub fn statuses(&self) -> Vec<Status> {
        let handshakes = self.state.handshakes.lock().expect("lock");
        handshakes.iter().map(|h| h.info.status).collect()
    }

    #[allow(dead_code)]
    pub fn cert(&self, index: usize) -> CertificateDer<'static> {
        self.state.handshakes.lock().expect("lock")[index]
            .cert
            .clone()
    }

    #[allow(dead_code)]
    pub fn connection(&self) -> server::Connection {
        let connection = self.state.connection.lock().expect("lock");
        server::Connection::from_quinn(connection.clone().expect("a connection"))
    }

    #[allow(dead_code)]
    pub fn quinn_connection(&self) -> quinn::Connection {
        let connection = self.state.connection.lock().expect("lock");
        connection.clone().expect("a connection")
    }

    /// Closes the current connection, so the client reconnects.
    #[allow(dead_code)]
    pub fn drop_connection(&self) {
        if let Some(connection) = self.state.connection.lock().expect("lock").take() {
            connection.close(0u32.into(), b"dropped");
        }
    }

    #[allow(dead_code)]
    pub async fn send_update(&self) -> Result<()> {
        self.connection().send_config_update_cmd().await
    }
}

pub async fn accept(endpoint: Endpoint, state: Arc<State>) {
    let mut connections = JoinSet::new();
    while let Some(incoming) = endpoint.accept().await {
        connections.spawn(serve(incoming, state.clone()));
    }
}

pub async fn serve(incoming: quinn::Incoming, state: Arc<State>) {
    let Ok(connection) = incoming.await else {
        return;
    };
    state.attempts.fetch_add(1, Ordering::SeqCst);
    let version_req = state.version_req.lock().expect("lock").clone();
    let Ok(info) = server::handshake(
        &connection,
        connection.remote_address(),
        &version_req,
        HIGHEST_PROTOCOL_VERSION,
    )
    .await
    else {
        return;
    };
    let cert = connection
        .peer_identity()
        .and_then(|identity| identity.downcast::<Vec<CertificateDer<'static>>>().ok())
        .and_then(|certs| certs.first().cloned())
        .expect("a client certificate");
    state
        .handshakes
        .lock()
        .expect("lock")
        .push(Handshake { info, cert });
    *state.connection.lock().expect("lock") = Some(connection.clone());

    let mut requests = JoinSet::new();
    while let Ok((mut send, mut recv)) = connection.accept_bi().await {
        let mut handler = Handler {
            state: state.clone(),
        };
        requests.spawn(async move {
            let _ = server::handle(&mut handler, &mut send, &mut recv, "reproduce.test").await;
        });
    }
}

pub struct Handler {
    pub state: Arc<State>,
}

#[async_trait]
impl server::Handler for Handler {
    async fn get_config(&self, _peer: &str) -> Result<String, String> {
        self.state.get_configs.fetch_add(1, Ordering::SeqCst);
        let delay = *self.state.delay.lock().expect("lock");
        sleep(delay).await;
        self.state
            .config
            .lock()
            .expect("lock")
            .clone()
            .ok_or_else(|| "config unavailable".to_string())
    }
}

/// The TLS files of a client.
pub struct Files {
    pub _dir: TempDir,
    pub files: TlsFiles,
}

impl Files {
    pub fn new(pki: &Pki, identity: &Identity) -> Result<Self> {
        let dir = tempfile::tempdir()?;
        let files = TlsFiles {
            cert: dir.path().join("cert.pem"),
            key: dir.path().join("key.pem"),
            ca_certs: vec![dir.path().join("ca.pem")],
        };
        let this = Self { _dir: dir, files };
        this.write_identity(identity)?;
        std::fs::write(&this.files.ca_certs[0], &pki.ca)?;
        Ok(this)
    }

    pub fn write_identity(&self, identity: &Identity) -> Result<()> {
        std::fs::write(&self.files.cert, &identity.cert)?;
        std::fs::write(&self.files.key, &identity.key)?;
        Ok(())
    }
}

/// Waits until `condition` holds.
#[allow(dead_code)]
pub async fn wait_until(what: &str, condition: impl Fn() -> bool) {
    let deadline = Instant::now() + WAIT;
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting until {what}");
        sleep(Duration::from_millis(20)).await;
    }
}

/// Captures what the client logs.
#[derive(Clone, Default)]
pub struct Logs(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Logs {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("lock").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Logs {
    /// Captures the logs of the current thread, which runs every task of a
    /// current-thread runtime.
    pub fn capture() -> (Self, tracing::subscriber::DefaultGuard) {
        let logs = Self::default();
        let writer = logs.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        (logs, tracing::subscriber::set_default(subscriber))
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().expect("lock")).into_owned()
    }
}

#[cfg(unix)]
pub fn send_signal(child: &std::process::Child, signal: libc::c_int) {
    let pid = libc::pid_t::try_from(child.id()).expect("a valid pid");
    // SAFETY: `kill` has no memory-safety preconditions.
    unsafe {
        libc::kill(pid, signal);
    }
}
