//! The Central Manager client of remote mode.
//!
//! The client connects to the Central Manager (`REview`) over review-protocol,
//! fetches the configuration with `get_config` and hands every valid one to
//! a [`ConfigRuntime`]. It keeps the applied configuration current: `REview`'s
//! `update_config` schedules a fetch, and a lost connection is reconnected,
//! after which the configuration is fetched again.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use review_protocol::client::{Connection, ConnectionBuilder};
use review_protocol::request::{self, HandlerError};
use review_protocol::types::Status;
use thiserror::Error;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::{error, info, warn};

use crate::config::remote::{self, RemoteConfig};
use crate::reload::ReloadFlag;

/// How long the client waits after a failed connect before it tries again.
pub const RETRY_INTERVAL: Duration = Duration::from_secs(5);

/// The agent name the client reports in the handshake.
const AGENT_NAME: &str = env!("CARGO_PKG_NAME");

/// The agent version the client reports in the handshake.
const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Takes every valid configuration the Central Manager provides.
#[async_trait]
pub trait ConfigRuntime: Send {
    /// Puts `config` in force.
    ///
    /// The client awaits each call before it starts the next fetch, so calls
    /// never overlap. A configuration equal to the one in force may be handed
    /// off again, and is no change.
    async fn apply(&mut self, config: RemoteConfig);
}

/// The paths of the TLS files the client connects with.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsFiles {
    /// The certificate presented to the Central Manager.
    pub cert: PathBuf,
    /// The private key of the certificate.
    pub key: PathBuf,
    /// The CA certificates the Central Manager's certificate is verified
    /// against.
    pub ca_certs: Vec<PathBuf>,
}

/// TLS material read from [`TlsFiles`] and checked to be usable.
#[derive(Clone)]
pub struct TlsMaterial {
    cert: Vec<u8>,
    key: Vec<u8>,
    ca_certs: Vec<Vec<u8>>,
}

impl std::fmt::Debug for TlsMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The key is never printed.
        f.debug_struct("TlsMaterial").finish_non_exhaustive()
    }
}

/// An error refusing the TLS material; each names the file it is about.
#[derive(Debug, Error)]
pub enum TlsError {
    // The I/O error is part of the message rather than its source, so the
    // reason is printed once, on the line naming the file.
    #[error("cannot read the {kind} file {}: {error}", path.display())]
    Read {
        kind: &'static str,
        path: PathBuf,
        error: io::Error,
    },
    #[error("invalid {kind} file {}: {reason}", path.display())]
    Invalid {
        kind: &'static str,
        path: PathBuf,
        reason: String,
    },
}

const CERT_KIND: &str = "certificate";
const KEY_KIND: &str = "private key";
const CA_KIND: &str = "CA certificate";

impl TlsMaterial {
    /// Reads and checks the TLS files.
    ///
    /// # Errors
    ///
    /// Returns an error naming the file if a file cannot be read, the
    /// certificate file holds no certificate, the key file holds no private
    /// key, a CA file holds no certificate, or review-protocol refuses one of
    /// them.
    pub fn read(files: &TlsFiles) -> Result<Self, TlsError> {
        let cert = read_file(CERT_KIND, &files.cert)?;
        let certs = rustls_pemfile::certs(&mut cert.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| invalid(CERT_KIND, &files.cert, error))?;
        if certs.is_empty() {
            return Err(invalid(CERT_KIND, &files.cert, "no certificate"));
        }

        let key = read_file(KEY_KIND, &files.key)?;
        match rustls_pemfile::private_key(&mut key.as_slice()) {
            Ok(Some(_)) => {}
            Ok(None) => return Err(invalid(KEY_KIND, &files.key, "no private key")),
            Err(error) => return Err(invalid(KEY_KIND, &files.key, error)),
        }

        // Neither builder call names a file, so each file is checked on its
        // own; `root_certs` replaces the roots on every call. The manager
        // endpoint and status play no part in what the builder accepts.
        let mut builder = ConnectionBuilder::new(
            "localhost",
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            AGENT_NAME,
            AGENT_VERSION,
            review_protocol::PROTOCOL_VERSION,
            Status::Idle,
            &cert,
            &key,
        )
        .map_err(|error| invalid(CERT_KIND, &files.cert, error))?;
        let mut ca_certs = Vec::with_capacity(files.ca_certs.len());
        for path in &files.ca_certs {
            let ca_cert = read_file(CA_KIND, path)?;
            let certs = rustls_pemfile::certs(&mut ca_cert.as_slice())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| invalid(CA_KIND, path, error))?;
            if certs.is_empty() {
                return Err(invalid(CA_KIND, path, "no certificate"));
            }
            builder
                .root_certs([&ca_cert])
                .map_err(|error| invalid(CA_KIND, path, error))?;
            ca_certs.push(ca_cert);
        }

        Ok(Self {
            cert,
            key,
            ca_certs,
        })
    }

    fn builder(&self, manager: &Manager, status: Status) -> io::Result<ConnectionBuilder> {
        let mut builder = ConnectionBuilder::new(
            &manager.server_name,
            manager.addr,
            AGENT_NAME,
            AGENT_VERSION,
            review_protocol::PROTOCOL_VERSION,
            status,
            &self.cert,
            &self.key,
        )?;
        builder.root_certs(&self.ca_certs)?;
        Ok(builder)
    }
}

fn read_file(kind: &'static str, path: &Path) -> Result<Vec<u8>, TlsError> {
    std::fs::read(path).map_err(|error| TlsError::Read {
        kind,
        path: path.to_path_buf(),
        error,
    })
}

fn invalid(kind: &'static str, path: &Path, reason: impl std::fmt::Display) -> TlsError {
    TlsError::Invalid {
        kind,
        path: path.to_path_buf(),
        reason: reason.to_string(),
    }
}

/// The Central Manager endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Manager {
    /// The name the manager's certificate is verified against.
    pub server_name: String,
    pub addr: SocketAddr,
}

/// The Central Manager client.
pub struct Client {
    manager: Manager,
    files: TlsFiles,
    /// The material of the last successful connect, or the startup material
    /// before the first one.
    material: TlsMaterial,
    /// Set by `SIGHUP`; the next connect re-reads `files`.
    tls_reload: ReloadFlag,
    /// Set by `SIGHUP`; while nothing is applied, it schedules a fetch.
    wake: ReloadFlag,
    retry_interval: Duration,
}

impl Client {
    /// Creates a client that connects with `material`, read from `files`.
    ///
    /// `tls_reload` and `wake` are two flags of the same reload signal:
    /// `tls_reload` was subscribed before `material` was read.
    #[must_use]
    pub fn new(
        manager: Manager,
        files: TlsFiles,
        material: TlsMaterial,
        tls_reload: ReloadFlag,
        wake: ReloadFlag,
    ) -> Self {
        Self {
            manager,
            files,
            material,
            tls_reload,
            wake,
            retry_interval: RETRY_INTERVAL,
        }
    }

    /// Sets how long the client waits after a failed connect.
    #[must_use]
    pub fn with_retry_interval(mut self, retry_interval: Duration) -> Self {
        self.retry_interval = retry_interval;
        self
    }

    /// Keeps the configuration `runtime` holds current until `shutdown`
    /// becomes `true` or its sender is dropped.
    ///
    /// Returns at once on shutdown, whatever the client is doing, after
    /// dropping the manager connection; an `apply` in progress is dropped.
    pub async fn run<R>(mut self, runtime: &mut R, mut shutdown: watch::Receiver<bool>)
    where
        R: ConfigRuntime + ?Sized,
    {
        tokio::select! {
            () = self.serve(runtime) => {}
            _ = shutdown.wait_for(|&shutdown| shutdown) => {}
        }
    }

    async fn serve<R>(&mut self, runtime: &mut R)
    where
        R: ConfigRuntime + ?Sized,
    {
        let mut applied = None;
        loop {
            let status = if applied.is_some() {
                Status::Ready
            } else {
                Status::Idle
            };
            let connection = self.connect(status).await;
            self.session(connection, runtime, &mut applied).await;
        }
    }

    /// Connects, retrying every `retry_interval` until a connect succeeds.
    async fn connect(&mut self, status: Status) -> Connection {
        info!("Connecting to the Central Manager at {}", self.manager.addr);
        loop {
            match self.try_connect(status).await {
                Ok(connection) => {
                    info!(
                        "Connected to the Central Manager at {} with status {status:?}",
                        self.manager.addr
                    );
                    return connection;
                }
                Err(error) => {
                    warn!(
                        "Cannot connect to the Central Manager at {}, retrying in {:?}: {error}",
                        self.manager.addr, self.retry_interval
                    );
                    tokio::time::sleep(self.retry_interval).await;
                }
            }
        }
    }

    /// Makes one connect attempt.
    ///
    /// With a reload pending, it re-reads the TLS files first and connects
    /// with them; if they are not valid or that connect fails, the same
    /// attempt connects with the last-known-good material, and the reload
    /// stays pending.
    async fn try_connect(&mut self, status: Status) -> io::Result<Connection> {
        if self.tls_reload.is_pending() {
            let ticket = self.tls_reload.ticket();
            match TlsMaterial::read(&self.files) {
                Ok(material) => match connect_with(&material, &self.manager, status).await {
                    Ok(connection) => {
                        info!("Connected with the reloaded TLS material");
                        self.material = material;
                        self.tls_reload.commit(ticket);
                        return Ok(connection);
                    }
                    Err(error) => {
                        warn!(
                            "Cannot connect with the reloaded TLS material, \
                             using the last known good: {error}"
                        );
                    }
                },
                Err(error) => {
                    warn!("Cannot reload the TLS material, using the last known good: {error}");
                }
            }
        }
        connect_with(&self.material, &self.manager, status).await
    }

    /// Serves one connection until it is lost, or until the first
    /// configuration is applied, so that the next connect reports `Ready`.
    ///
    /// The connection and every task serving its streams are dropped on
    /// return.
    async fn session<R>(
        &mut self,
        connection: Connection,
        runtime: &mut R,
        applied: &mut Option<RemoteConfig>,
    ) where
        R: ConfigRuntime + ?Sized,
    {
        // Kept for the whole session, so `updates` never sees it closed.
        let (update, mut updates) = watch::channel(());
        let mut streams = JoinSet::new();
        streams.spawn(accept_requests(connection.clone(), update.clone()));

        loop {
            // A fetch serves every `update_config` and `SIGHUP` before it
            // starts, so any number of them during one fetch schedule
            // exactly one more.
            updates.borrow_and_update();
            let ticket = self.wake.ticket();
            self.wake.commit(ticket);

            let was_idle = applied.is_none();
            apply(&connection, runtime, applied).await;
            if was_idle && applied.is_some() {
                info!("Reconnecting to report the applied configuration");
                return;
            }

            // Waits for what schedules the next fetch.
            tokio::select! {
                _ = streams.join_next() => {
                    warn!("Lost the connection to the Central Manager");
                    return;
                }
                _ = updates.changed() => {}
                () = self.wake.requested(), if was_idle => {}
            }
        }
    }
}

async fn connect_with(
    material: &TlsMaterial,
    manager: &Manager,
    status: Status,
) -> io::Result<Connection> {
    material.builder(manager, status)?.connect().await
}

/// Fetches, validates and hands off the configuration.
///
/// A failed fetch or an invalid configuration keeps `applied`.
async fn apply<R>(connection: &Connection, runtime: &mut R, applied: &mut Option<RemoteConfig>)
where
    R: ConfigRuntime + ?Sized,
{
    let keeping = if applied.is_some() {
        "keeping the applied configuration"
    } else {
        "staying idle"
    };
    let text = match connection.get_config().await {
        Ok(text) => text,
        Err(error) => {
            warn!("Cannot fetch the configuration from the Central Manager, {keeping}: {error}");
            return;
        }
    };
    let config = match remote::parse(&text) {
        Ok(config) => config,
        Err(error) => {
            // The parser's error may quote the offending line, never the
            // whole configuration.
            error!("Invalid configuration from the Central Manager, {keeping}: {error}");
            return;
        }
    };
    *applied = Some(config.clone());
    runtime.apply(config).await;
}

/// Accepts every stream the manager opens and serves each in its own task,
/// until the connection is lost.
///
/// Dropping the future aborts the tasks serving the streams.
async fn accept_requests(connection: Connection, update: watch::Sender<()>) {
    let mut requests = JoinSet::new();
    loop {
        let (mut send, mut recv) = match connection.accept_bi().await {
            Ok(streams) => streams,
            Err(error) => {
                warn!("Cannot accept a request from the Central Manager: {error}");
                return;
            }
        };
        while requests.try_join_next().is_some() {}
        let mut handler = RequestHandler {
            update: update.clone(),
        };
        requests.spawn(async move {
            if let Err(error) = request::handle(&mut handler, &mut send, &mut recv).await {
                let (HandlerError::RecvError(source) | HandlerError::SendError(source)) = &error;
                warn!("Cannot serve a request from the Central Manager: {error}: {source}");
            }
        });
    }
}

/// Answers the manager's requests: `update_config` schedules a fetch, and
/// every other request is not supported.
struct RequestHandler {
    update: watch::Sender<()>,
}

#[async_trait]
impl request::Handler for RequestHandler {
    async fn update_config(&mut self) -> Result<(), String> {
        info!("Configuration update requested by the Central Manager");
        self.update.send_replace(());
        Ok(())
    }
}
