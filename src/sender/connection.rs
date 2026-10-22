//! The owner of one Giganto ingest connection.

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use quinn::{Connection, Endpoint};
use tokio::{sync::watch, task};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use super::{
    AckDelivery, AckReceiver, GigantoStream, ReconnectOutcome, SenderError, TimeoutPolicy,
    connect_and_handshake, create_endpoint,
};
use crate::reload::{ReloadFlag, ReloadSignal, ReloadTicket};

/// Delay between closing a failed connection and connecting again.
const RECONNECT_DELAY: Duration = Duration::from_secs(2);

/// Where and as whom a [`GigantoConnection`] connects.
#[derive(Clone, Debug)]
pub struct ConnectionConfig {
    pub cert: String,
    pub key: String,
    pub ca_certs: Vec<String>,
    pub server_addr: SocketAddr,
    pub server_name: String,
}

/// Selects what a stream does after a write error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamErrorPolicy {
    /// Every write error closes and reconnects the connection, as local
    /// mode does.
    Reconnect,

    /// A write error on a connection that is still live reopens only the
    /// failed stream; a lost connection is reconnected.
    ReopenStream,
}

/// Owns one QUIC connection to a Giganto ingest server, shared by every
/// [`GigantoStream`] opened on it.
///
/// Each connection the owner establishes has a generation number, starting
/// at 0. A stream that fails on generation *g* asks for a connection newer
/// than *g* through [`reconnect`](Self::reconnect): the first such request
/// closes generation *g* and reconnects, every concurrent request for *g*
/// waits for and receives that reconnect's result, and a request for a
/// generation that is already replaced returns the current connection
/// without closing it.
///
/// Cloning is cheap; clones share the connection.
#[derive(Clone, Debug)]
pub struct GigantoConnection {
    shared: Arc<Shared>,
}

#[derive(Debug)]
struct Shared {
    config: ConnectionConfig,
    policy: StreamErrorPolicy,
    /// Cancels connecting and reconnecting: a child of the caller's connect
    /// token, also cancelled by `close`. Streams have their own tokens.
    token: CancellationToken,
    state: Mutex<State>,
}

#[derive(Debug)]
struct State {
    /// The endpoint of the current connection.
    endpoint: Endpoint,
    /// The live connection, or `None` while a reconnect is replacing it,
    /// after a reconnect failed, or after `close`.
    conn: Option<Connection>,
    generation: u64,
    reload: ReloadFlag,
    /// The last-known-good endpoint, kept while a reload applied under
    /// [`StreamErrorPolicy::Reconnect`] waits for its first stream.
    fallback: Option<Fallback>,
    /// Delivers the result of the reconnect in flight, if any.
    in_flight: Option<watch::Receiver<Option<SharedReconnect>>>,
    closed: bool,
}

/// A reload not yet committed: the connection of `generation` runs on the
/// rebuilt endpoint, but no stream has opened on it yet.
///
/// Local mode commits a reload only once its stream opens, as 0.25.1 did, so
/// a rebuilt connection that completes its handshake but cannot open a
/// stream falls back to `endpoint` and leaves the reload pending.
#[derive(Debug)]
struct Fallback {
    generation: u64,
    endpoint: Endpoint,
    ticket: ReloadTicket,
}

/// The result of one reconnect, handed to every stream that waited on it.
type SharedReconnect = std::result::Result<Lease, Arc<SenderError>>;

/// A connection a stream can open its stream on.
#[derive(Clone, Debug)]
pub(super) struct Lease {
    pub(super) conn: Connection,
    pub(super) generation: u64,
    pub(super) outcome: ReconnectOutcome,
}

/// What [`GigantoConnection::current`] finds.
pub(super) enum Current {
    Live(Connection, u64),
    /// The connection of this generation is gone and not replaced yet.
    Lost(u64),
    Closed,
}

/// A connection a reconnect established, before it is installed.
struct Attempt {
    conn: Connection,
    /// The rebuilt endpoint and the reload requests its material reflects,
    /// when a pending reload was applied.
    reloaded: Option<(Endpoint, ReloadTicket)>,
    deferred: Option<SenderError>,
}

impl GigantoConnection {
    /// Connects to the Giganto ingest server and completes the handshake.
    ///
    /// Subscribes to `reload` before reading the TLS files, so a reload
    /// requested during this connect is applied at the first reconnect. If
    /// the server is temporarily unreachable (`TimedOut`), retries
    /// indefinitely; `token` cancels connecting now and on every reconnect.
    ///
    /// # Errors
    ///
    /// Returns an error if the TLS material is invalid, the endpoint cannot
    /// be created, the connection fails with anything but a timeout, the
    /// handshake fails, or `token` is cancelled.
    pub async fn connect(
        config: ConnectionConfig,
        policy: StreamErrorPolicy,
        reload: &ReloadSignal,
        token: CancellationToken,
    ) -> std::result::Result<Self, SenderError> {
        let reload = reload.subscribe();
        let endpoint = build_endpoint(&config, "failed to join endpoint creation task").await?;
        let conn = connect_and_handshake(
            &endpoint,
            config.server_addr,
            &config.server_name,
            TimeoutPolicy::RetryForever,
            &token,
        )
        .await?;
        info!(
            "Connected to data store ingest server at {}",
            config.server_addr
        );

        Ok(Self {
            shared: Arc::new(Shared {
                config,
                policy,
                token: token.child_token(),
                state: Mutex::new(State {
                    endpoint,
                    conn: Some(conn),
                    generation: 0,
                    reload,
                    fallback: None,
                    in_flight: None,
                    closed: false,
                }),
            }),
        })
    }

    /// Opens a new stream on the current connection.
    ///
    /// If the connection is lost, asks for a newer one first, as a write
    /// error does. `token` belongs to the stream: it ends the wait for the
    /// close ACK and stops the stream's ACK receiver. With
    /// [`AckDelivery::Deliver`], the returned receiver yields every ACK
    /// timestamp of the stream, in order.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection is closed, a needed reconnect
    /// fails, or `token` is cancelled.
    pub async fn open_stream(
        &self,
        token: CancellationToken,
        delivery: AckDelivery,
    ) -> std::result::Result<(GigantoStream, Option<AckReceiver>), SenderError> {
        GigantoStream::open(self.clone(), token, delivery).await
    }

    /// Asks for a connection newer than `failed_generation`.
    ///
    /// Closes and replaces the connection only if it is still generation
    /// `failed_generation` and no reconnect is in flight; otherwise waits for
    /// the reconnect in flight or returns the newer connection at once.
    ///
    /// # Errors
    ///
    /// Returns the error the reconnect failed with, shared by every caller
    /// that waited on it: [`SenderError::Cancelled`] when the connect token
    /// was cancelled, [`SenderError::Closed`] after [`close`](Self::close),
    /// and otherwise a [`SenderError::Reconnect`].
    pub async fn reconnect(
        &self,
        failed_generation: u64,
    ) -> std::result::Result<ReconnectOutcome, SenderError> {
        self.reconnect_lease(failed_generation)
            .await
            .map(|lease| lease.outcome)
    }

    /// Returns the generation of the current or last connection.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.shared.lock().generation
    }

    /// Returns whether a reload is pending for this connection.
    ///
    /// Under [`StreamErrorPolicy::Reconnect`], a reload stays pending after
    /// the reconnect that applies it until a stream opens on it.
    #[must_use]
    pub fn reload_pending(&self) -> bool {
        self.shared.lock().reload.is_pending()
    }

    #[must_use]
    pub fn policy(&self) -> StreamErrorPolicy {
        self.shared.policy
    }

    /// Closes the connection with `log_done` and waits for the endpoint to
    /// become idle.
    ///
    /// Streams should be closed first; a stream still open is cut off. A
    /// reconnect in flight ends, and it and every later reconnect or stream
    /// open fail with [`SenderError::Closed`].
    pub async fn close(&self) {
        let (conn, endpoint) = {
            let mut state = self.shared.lock();
            state.closed = true;
            (state.conn.take(), state.endpoint.clone())
        };
        self.shared.token.cancel();
        if let Some(conn) = conn {
            conn.close(0u32.into(), b"log_done");
            endpoint.wait_idle().await;
        }
    }

    pub(super) fn current(&self) -> Current {
        let state = self.shared.lock();
        if state.closed {
            Current::Closed
        } else if let Some(conn) = &state.conn {
            Current::Live(conn.clone(), state.generation)
        } else {
            Current::Lost(state.generation)
        }
    }

    pub(super) async fn reconnect_lease(
        &self,
        failed_generation: u64,
    ) -> std::result::Result<Lease, SenderError> {
        let mut result = {
            let mut state = self.shared.lock();
            if state.closed {
                return Err(SenderError::Closed);
            }
            if state.generation > failed_generation
                && let Some(conn) = &state.conn
            {
                return Ok(Lease {
                    conn: conn.clone(),
                    generation: state.generation,
                    outcome: ReconnectOutcome::Reconnected,
                });
            }
            if let Some(in_flight) = &state.in_flight {
                in_flight.clone()
            } else {
                // A reload no stream confirmed stays pending for this
                // reconnect, which starts from the last-known-good endpoint.
                if let Some(fallback) = state.fallback.take() {
                    state.endpoint = fallback.endpoint;
                }
                self.start_reconnect(&mut state, None)
            }
        };
        Self::wait_for_reconnect(&mut result).await
    }

    /// Commits a reload that waits for its first stream, once a stream has
    /// opened on the connection of `generation`.
    pub(super) fn confirm(&self, generation: u64) {
        let mut state = self.shared.lock();
        if let Some(fallback) = state
            .fallback
            .take_if(|fallback| fallback.generation == generation)
        {
            state.commit_reload(fallback.ticket);
        }
    }

    /// Falls back to the last-known-good endpoint after a stream failed to
    /// open, with `error`, on the connection of `generation`.
    ///
    /// Applies only while that connection runs on a rebuilt endpoint no
    /// stream has opened on: the rebuilt connection is closed, the reload
    /// stays pending, and the connection made with the last-known-good
    /// endpoint is returned with [`ReconnectOutcome::ReloadDeferred`].
    ///
    /// # Errors
    ///
    /// Returns `error` itself when there is nothing to fall back to, and
    /// otherwise the error the fallback reconnect failed with.
    pub(super) async fn fall_back(
        &self,
        generation: u64,
        error: SenderError,
    ) -> std::result::Result<Lease, SenderError> {
        let mut result = {
            let mut state = self.shared.lock();
            if state.closed {
                return Err(SenderError::Closed);
            }
            let Some(fallback) = state
                .fallback
                .take_if(|fallback| fallback.generation == generation)
            else {
                return Err(error);
            };
            warn!(
                "Reload candidate stream setup failed; \
                 falling back to last-known-good endpoint and \
                 leaving reload pending: {error}"
            );
            state.endpoint = fallback.endpoint;
            self.start_reconnect(&mut state, Some(error))
        };
        Self::wait_for_reconnect(&mut result).await
    }

    /// Starts a reconnect and records it as the one in flight. With
    /// `deferred`, the reconnect falls back at once to the last-known-good
    /// endpoint, reporting the reload deferred by `deferred`.
    fn start_reconnect(
        &self,
        state: &mut State,
        deferred: Option<SenderError>,
    ) -> watch::Receiver<Option<SharedReconnect>> {
        let (sender, receiver) = watch::channel(None);
        state.in_flight = Some(receiver.clone());
        tokio::spawn(run_reconnect(Arc::clone(&self.shared), sender, deferred));
        receiver
    }

    async fn wait_for_reconnect(
        result: &mut watch::Receiver<Option<SharedReconnect>>,
    ) -> std::result::Result<Lease, SenderError> {
        let shared = result
            .wait_for(Option::is_some)
            .await
            .map_err(|source| SenderError::context("reconnect task ended unexpectedly", source))?
            .clone();
        match shared {
            Some(Ok(lease)) => Ok(lease),
            Some(Err(error)) => Err(match *error {
                SenderError::Cancelled => SenderError::Cancelled,
                SenderError::Closed => SenderError::Closed,
                _ => SenderError::Reconnect(error),
            }),
            None => unreachable!("wait_for returns only a completed reconnect"),
        }
    }

    #[cfg(test)]
    pub(super) fn endpoint_addr(&self) -> SocketAddr {
        self.shared
            .lock()
            .endpoint
            .local_addr()
            .expect("client endpoint should have a local address")
    }
}

impl State {
    fn commit_reload(&mut self, ticket: ReloadTicket) {
        self.reload.commit(ticket);
        info!("QUIC endpoint rebuilt successfully");
    }
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Closes the current connection and establishes a new one.
    ///
    /// When a reload is pending, a replacement endpoint is built from the
    /// configured cert/key/CA paths and used for the handshake so that
    /// externally rotated certificates take effect. The replacement endpoint
    /// is only committed, and the reload requests made before its files were
    /// read are only cleared, after its handshake succeeds and, under
    /// [`StreamErrorPolicy::Reconnect`], after a stream opens on it. If the
    /// rebuild fails, or the rebuilt endpoint cannot complete the handshake,
    /// the last-known-good endpoint is used and the reload is reported
    /// deferred.
    ///
    /// With `fallback`, the error a rebuilt connection's stream setup failed
    /// with, the reconnect skips its delay and the reload and connects with
    /// the last-known-good endpoint at once, reporting the reload deferred.
    ///
    /// The reload candidate uses `TimeoutPolicy::ReturnOnTimeout` so a hung
    /// handshake on the rebuilt endpoint falls back rather than retrying
    /// forever; the last-known-good path keeps `TimeoutPolicy::RetryForever`
    /// so transient server outages reconnect on their own.
    async fn reconnect_now(
        &self,
        fallback: Option<SenderError>,
    ) -> std::result::Result<Attempt, SenderError> {
        let old = self.lock().conn.take();
        if let Some(old) = old {
            old.close(0u32.into(), b"reconnect");
        }
        if fallback.is_none() {
            tokio::select! {
                () = tokio::time::sleep(RECONNECT_DELAY) => {}
                () = self.token.cancelled() => return Err(SenderError::Cancelled),
            }
        }

        let (endpoint, ticket) = {
            let state = self.lock();
            let ticket =
                (fallback.is_none() && state.reload.is_pending()).then(|| state.reload.ticket());
            (state.endpoint.clone(), ticket)
        };

        let mut deferred = fallback;
        if let Some(ticket) = ticket {
            info!("Reload requested, rebuilding QUIC endpoint from fresh TLS material");
            match build_endpoint(&self.config, "failed to join endpoint rebuild task").await {
                Ok(candidate) => {
                    match connect_and_handshake(
                        &candidate,
                        self.config.server_addr,
                        &self.config.server_name,
                        TimeoutPolicy::ReturnOnTimeout,
                        &self.token,
                    )
                    .await
                    {
                        Ok(conn) => {
                            return Ok(Attempt {
                                conn,
                                reloaded: Some((candidate, ticket)),
                                deferred: None,
                            });
                        }
                        Err(error) => {
                            warn!(
                                "Reload candidate handshake failed; \
                                 falling back to last-known-good endpoint and \
                                 leaving reload pending: {error}"
                            );
                            deferred = Some(error);
                        }
                    }
                }
                Err(error) => {
                    warn!(
                        "Failed to rebuild QUIC endpoint; keeping \
                         last-known-good endpoint and leaving reload \
                         pending: {error}"
                    );
                    deferred = Some(error);
                }
            }
        }

        let conn = connect_and_handshake(
            &endpoint,
            self.config.server_addr,
            &self.config.server_name,
            TimeoutPolicy::RetryForever,
            &self.token,
        )
        .await?;
        Ok(Attempt {
            conn,
            reloaded: None,
            deferred,
        })
    }
}

/// Runs one reconnect to completion and publishes its result to every
/// waiting stream, even if the stream that started it stops waiting.
async fn run_reconnect(
    shared: Arc<Shared>,
    result: watch::Sender<Option<SharedReconnect>>,
    fallback: Option<SenderError>,
) {
    let attempt = shared.reconnect_now(fallback).await;
    let published = {
        let mut state = shared.lock();
        state.in_flight = None;
        match attempt {
            _ if state.closed => {
                if let Ok(attempt) = attempt {
                    attempt.conn.close(0u32.into(), b"log_done");
                }
                Err(Arc::new(SenderError::Closed))
            }
            Ok(Attempt {
                conn,
                reloaded,
                deferred,
            }) => {
                state.generation += 1;
                if let Some((endpoint, ticket)) = reloaded {
                    let last_known_good = std::mem::replace(&mut state.endpoint, endpoint);
                    if shared.policy == StreamErrorPolicy::Reconnect {
                        state.fallback = Some(Fallback {
                            generation: state.generation,
                            endpoint: last_known_good,
                            ticket,
                        });
                    } else {
                        state.commit_reload(ticket);
                    }
                }
                state.conn = Some(conn.clone());
                Ok(Lease {
                    conn,
                    generation: state.generation,
                    outcome: match deferred {
                        Some(error) => ReconnectOutcome::ReloadDeferred(Arc::new(error)),
                        None => ReconnectOutcome::Reconnected,
                    },
                })
            }
            Err(error) => Err(Arc::new(error)),
        }
    };
    result.send_replace(Some(published));
}

/// Builds a QUIC endpoint from the configured TLS file paths.
async fn build_endpoint(
    config: &ConnectionConfig,
    join_context: &'static str,
) -> std::result::Result<Endpoint, SenderError> {
    let cert = config.cert.clone();
    let key = config.key.clone();
    let ca_certs = config.ca_certs.clone();
    task::spawn_blocking(move || create_endpoint(&cert, &key, &ca_certs))
        .await
        .map_err(|source| SenderError::context(join_context, source))?
}

#[cfg(test)]
mod tests {
    use std::fs;

    use anyhow::Context;
    use giganto_client::{RawEventKind, connection::server_handshake};
    use quinn::VarInt;
    use tempfile::tempdir;
    use tokio::time::{Duration, timeout};

    use super::super::test_support::{
        RECONNECT_TIMEOUT, TEST_TIMEOUT, accept_connection, accept_server_stream,
        build_server_endpoint, connect_test_connection, connects_from, copied_fixture_config,
        fixture_config,
    };
    use super::*;
    use crate::sender::{CloseAck, REQUIRED_GIGANTO_VERSION};

    /// Writes batches until the stream reports a write error.
    async fn write_until_error(stream: &mut GigantoStream) {
        timeout(TEST_TIMEOUT, async {
            while stream.send_batch(&[(1, b"x".to_vec())]).await.is_ok() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("writes should fail once the stream or connection is gone");
    }

    async fn open_log_only(connection: &GigantoConnection) -> GigantoStream {
        connection
            .open_stream(CancellationToken::new(), AckDelivery::LogOnly)
            .await
            .expect("a stream should open on the live connection")
            .0
    }

    #[tokio::test]
    async fn concurrent_write_errors_on_one_generation_reconnect_once() {
        let reload = ReloadSignal::new();
        let (connection, session) = connect_test_connection(
            StreamErrorPolicy::ReopenStream,
            &reload,
            CancellationToken::new(),
        )
        .await
        .expect("connection should be established");
        let mut first = open_log_only(&connection).await;
        let mut second = open_log_only(&connection).await;

        session.connection.close(0u32.into(), b"server-gone");
        write_until_error(&mut first).await;
        write_until_error(&mut second).await;

        let server_endpoint = session.server_endpoint.clone();
        let client = session.connection.remote_address();
        let server_task = tokio::spawn(async move {
            let reconnected = accept_connection(&server_endpoint, RECONNECT_TIMEOUT).await?;
            let extra = connects_from(&server_endpoint, client, Duration::from_secs(3)).await;
            Ok::<_, anyhow::Error>((reconnected, !extra))
        });

        let (first_outcome, second_outcome) = tokio::join!(first.recover(), second.recover());
        assert!(matches!(
            first_outcome.expect("first stream should recover"),
            ReconnectOutcome::Reconnected
        ));
        assert!(matches!(
            second_outcome.expect("second stream should recover"),
            ReconnectOutcome::Reconnected
        ));
        let (_reconnected, no_second_reconnect) = server_task
            .await
            .expect("server task should join")
            .expect("server should accept the reconnect");
        assert!(
            no_second_reconnect,
            "concurrent write errors on one generation must reconnect exactly once",
        );
        assert_eq!(connection.generation(), 1);
        assert_eq!(first.generation(), 1);
        assert_eq!(second.generation(), 1);
    }

    #[tokio::test]
    async fn reconnect_for_an_older_generation_keeps_the_newer_connection() {
        let reload = ReloadSignal::new();
        let (connection, session) = connect_test_connection(
            StreamErrorPolicy::ReopenStream,
            &reload,
            CancellationToken::new(),
        )
        .await
        .expect("connection should be established");

        let (outcome, newer) = tokio::join!(
            connection.reconnect(0),
            accept_connection(&session.server_endpoint, RECONNECT_TIMEOUT),
        );
        outcome.expect("reconnect should succeed");
        let newer = newer.expect("server should accept the reconnect");
        assert_eq!(connection.generation(), 1);

        let outcome = timeout(Duration::from_millis(500), connection.reconnect(0))
            .await
            .expect("a stale generation must not wait for a reconnect")
            .expect("a stale generation gets the current connection");
        assert!(matches!(outcome, ReconnectOutcome::Reconnected));
        assert_eq!(connection.generation(), 1);
        assert!(
            newer.close_reason().is_none(),
            "a request for an older generation must never close a newer connection",
        );
        assert!(
            !connects_from(
                &session.server_endpoint,
                newer.remote_address(),
                Duration::from_secs(3),
            )
            .await,
            "no further connection may be made for a stale generation",
        );
    }

    #[tokio::test]
    async fn waiting_streams_share_a_cancelled_reconnect() {
        let reload = ReloadSignal::new();
        let token = CancellationToken::new();
        let (connection, session) =
            connect_test_connection(StreamErrorPolicy::ReopenStream, &reload, token.clone())
                .await
                .expect("connection should be established");
        let mut first = open_log_only(&connection).await;
        let mut second = open_log_only(&connection).await;
        session.connection.close(0u32.into(), b"server-gone");
        write_until_error(&mut first).await;
        write_until_error(&mut second).await;

        tokio::spawn({
            let token = token.clone();
            async move {
                tokio::time::sleep(Duration::from_millis(300)).await;
                token.cancel();
            }
        });
        let (first_result, second_result) = timeout(TEST_TIMEOUT, async {
            tokio::join!(first.recover(), second.recover())
        })
        .await
        .expect("cancellation should end the reconnect for every waiter");
        assert!(matches!(first_result, Err(SenderError::Cancelled)));
        assert!(matches!(second_result, Err(SenderError::Cancelled)));
        assert_eq!(connection.generation(), 0);
    }

    #[tokio::test]
    async fn waiting_streams_share_a_failed_reconnect() {
        let reload = ReloadSignal::new();
        let (connection, session) = connect_test_connection(
            StreamErrorPolicy::ReopenStream,
            &reload,
            CancellationToken::new(),
        )
        .await
        .expect("connection should be established");
        let mut first = open_log_only(&connection).await;
        let mut second = open_log_only(&connection).await;
        session.connection.close(0u32.into(), b"server-gone");
        write_until_error(&mut first).await;
        write_until_error(&mut second).await;

        let server_endpoint = session.server_endpoint.clone();
        let server_task = tokio::spawn(async move {
            let incoming = timeout(RECONNECT_TIMEOUT, server_endpoint.accept())
                .await
                .context("server should see the reconnect")?
                .context("server endpoint should stay open")?;
            let conn = incoming.await.context("QUIC setup should complete")?;
            let _ = server_handshake(&conn, "0.0.1").await;
            let extra = connects_from(
                &server_endpoint,
                conn.remote_address(),
                Duration::from_secs(3),
            )
            .await;
            Ok::<_, anyhow::Error>(!extra)
        });
        let (first_result, second_result) = tokio::join!(first.recover(), second.recover());
        for result in [first_result, second_result] {
            let error = result.expect_err("the failed reconnect must reach every waiter");
            assert!(
                matches!(error.root(), SenderError::Handshake(_)),
                "every waiter must get the reconnect's own error, got {error:?}",
            );
        }
        assert!(
            server_task
                .await
                .expect("server task should join")
                .expect("server should see one reconnect"),
            "one failed reconnect must be shared, not repeated per stream",
        );
    }

    #[tokio::test]
    async fn stream_error_on_live_connection_reopens_only_that_stream() {
        let reload = ReloadSignal::new();
        let (connection, session) = connect_test_connection(
            StreamErrorPolicy::ReopenStream,
            &reload,
            CancellationToken::new(),
        )
        .await
        .expect("connection should be established");
        let mut failing = open_log_only(&connection).await;
        let mut other = open_log_only(&connection).await;
        failing
            .send_header(RawEventKind::Log)
            .await
            .expect("header should be sent");
        other
            .send_header(RawEventKind::Dns)
            .await
            .expect("header should be sent");
        let (_failing_send, mut failing_recv) = accept_server_stream(&session.connection)
            .await
            .expect("server should accept the first stream");
        let (_other_send, mut other_recv) = accept_server_stream(&session.connection)
            .await
            .expect("server should accept the second stream");

        failing_recv
            .stop(VarInt::from_u32(7))
            .expect("server should stop the stream");
        write_until_error(&mut failing).await;
        let outcome = failing
            .recover()
            .await
            .expect("a stream error on a live connection should reopen the stream");
        assert!(matches!(outcome, ReconnectOutcome::StreamReopened));
        assert_eq!(connection.generation(), 0);
        assert_eq!(failing.generation(), 0);

        failing
            .send_header(RawEventKind::Log)
            .await
            .expect("the reopened stream needs its header again");
        let (_reopened_send, mut reopened_recv) = accept_server_stream(&session.connection)
            .await
            .expect("the reopened stream should arrive on the same connection");
        let mut header = [0_u8; 4];
        giganto_client::ingest::receive_record_header(&mut reopened_recv, &mut header)
            .await
            .expect("server should receive the reopened stream's header");
        assert_eq!(header, u32::from(RawEventKind::Log).to_le_bytes());

        other
            .send_batch(&[(5, b"still here".to_vec())])
            .await
            .expect("the other stream keeps sending");
        let mut header = [0_u8; 4];
        giganto_client::ingest::receive_record_header(&mut other_recv, &mut header)
            .await
            .expect("server should receive the other header");
        let batch = super::super::test_support::recv_batch(&mut other_recv)
            .await
            .expect("the other stream's batch should arrive");
        assert_eq!(batch, vec![(5, b"still here".to_vec())]);
        assert!(session.connection.close_reason().is_none());
        assert!(
            !connects_from(
                &session.server_endpoint,
                session.connection.remote_address(),
                Duration::from_secs(3),
            )
            .await,
            "reopening a stream must not reconnect",
        );
    }

    #[tokio::test]
    async fn stream_error_on_live_connection_reconnects_in_local_mode() {
        let reload = ReloadSignal::new();
        let (connection, session) = connect_test_connection(
            StreamErrorPolicy::Reconnect,
            &reload,
            CancellationToken::new(),
        )
        .await
        .expect("connection should be established");
        let mut stream = open_log_only(&connection).await;
        stream
            .send_header(RawEventKind::Log)
            .await
            .expect("header should be sent");
        let (_send, mut recv) = accept_server_stream(&session.connection)
            .await
            .expect("server should accept the stream");
        recv.stop(VarInt::from_u32(7))
            .expect("server should stop the stream");
        write_until_error(&mut stream).await;

        let (outcome, reconnected) = tokio::join!(
            stream.recover(),
            accept_connection(&session.server_endpoint, RECONNECT_TIMEOUT),
        );
        assert!(matches!(
            outcome.expect("local mode should reconnect"),
            ReconnectOutcome::Reconnected
        ));
        reconnected.expect("server should accept the reconnect");
        assert_eq!(connection.generation(), 1);
        assert!(session.connection.close_reason().is_some());
    }

    #[tokio::test]
    async fn streams_open_after_another_stream_closed() {
        let reload = ReloadSignal::new();
        let (connection, session) = connect_test_connection(
            StreamErrorPolicy::ReopenStream,
            &reload,
            CancellationToken::new(),
        )
        .await
        .expect("connection should be established");
        let mut first = open_log_only(&connection).await;
        let close = first.close().await.expect("a header-less close succeeds");
        assert_eq!(close, CloseAck::NotSent);

        let mut second = open_log_only(&connection).await;
        second
            .send_header(RawEventKind::Log)
            .await
            .expect("a stream opened after another closed can send");
        assert_eq!(second.generation(), 0);
        accept_server_stream(&session.connection)
            .await
            .expect("server should accept the new stream on the same connection");
        assert!(session.connection.close_reason().is_none());
    }

    #[tokio::test]
    async fn reopen_on_a_lost_connection_asks_for_a_newer_one() {
        let reload = ReloadSignal::new();
        let (connection, session) = connect_test_connection(
            StreamErrorPolicy::ReopenStream,
            &reload,
            CancellationToken::new(),
        )
        .await
        .expect("connection should be established");
        let mut stream = open_log_only(&connection).await;
        session.connection.close(0u32.into(), b"server-gone");
        write_until_error(&mut stream).await;

        let (outcome, reconnected) = tokio::join!(
            stream.reopen(),
            accept_connection(&session.server_endpoint, RECONNECT_TIMEOUT),
        );
        assert!(matches!(
            outcome.expect("reopen should reconnect"),
            ReconnectOutcome::Reconnected
        ));
        reconnected.expect("server should accept the reconnect");
        assert_eq!(stream.generation(), 1);
    }

    #[tokio::test]
    async fn closed_connection_refuses_reconnect_and_streams() {
        let reload = ReloadSignal::new();
        let (connection, session) = connect_test_connection(
            StreamErrorPolicy::ReopenStream,
            &reload,
            CancellationToken::new(),
        )
        .await
        .expect("connection should be established");
        let ((), closed) = tokio::join!(connection.close(), session.connection.closed());
        assert!(
            matches!(
                &closed,
                quinn::ConnectionError::ApplicationClosed(close) if &close.reason[..] == b"log_done"
            ),
            "close must close the connection with log_done, got {closed:?}",
        );
        assert!(matches!(
            connection.reconnect(0).await,
            Err(SenderError::Closed)
        ));
        assert!(matches!(
            connection
                .open_stream(CancellationToken::new(), AckDelivery::LogOnly)
                .await,
            Err(SenderError::Closed)
        ));
    }

    #[tokio::test]
    async fn close_ends_a_reconnect_in_flight() {
        let reload = ReloadSignal::new();
        let (connection, session) = connect_test_connection(
            StreamErrorPolicy::ReopenStream,
            &reload,
            CancellationToken::new(),
        )
        .await
        .expect("connection should be established");
        let reconnect = tokio::spawn({
            let connection = connection.clone();
            async move { connection.reconnect(0).await }
        });
        // Let the reconnect start and close generation 0.
        timeout(TEST_TIMEOUT, session.connection.closed())
            .await
            .expect("the reconnect should close the failed connection");

        connection.close().await;
        let result = timeout(Duration::from_millis(500), reconnect)
            .await
            .expect("close must end the reconnect in flight at once")
            .expect("reconnect task should join");
        assert!(
            matches!(result, Err(SenderError::Closed)),
            "a reconnect ended by close must report Closed, got {result:?}",
        );
        assert!(
            !connects_from(
                &session.server_endpoint,
                session.connection.remote_address(),
                Duration::from_secs(3),
            )
            .await,
            "a closed connection must not connect again",
        );
    }

    #[tokio::test]
    async fn reconnect_reuses_endpoint_without_reload() {
        let reload = ReloadSignal::new();
        let (connection, session) = connect_test_connection(
            StreamErrorPolicy::Reconnect,
            &reload,
            CancellationToken::new(),
        )
        .await
        .expect("connection should be established");
        let endpoint_addr = connection.endpoint_addr();
        assert!(!connection.reload_pending());

        let (outcome, server) = tokio::join!(
            connection.reconnect(0),
            accept_connection(&session.server_endpoint, RECONNECT_TIMEOUT),
        );
        outcome.expect("reconnect without reload should succeed");
        server.expect("server handshake should succeed");
        assert_eq!(
            endpoint_addr,
            connection.endpoint_addr(),
            "endpoint should be reused when reload is not requested"
        );
    }

    #[tokio::test]
    async fn reload_causes_endpoint_rebuild_on_next_reconnect() {
        let reload = ReloadSignal::new();
        let (connection, session) = connect_test_connection(
            StreamErrorPolicy::Reconnect,
            &reload,
            CancellationToken::new(),
        )
        .await
        .expect("connection should be established");
        let endpoint_addr = connection.endpoint_addr();

        // Simulate SIGHUP.
        reload.request();
        assert!(connection.reload_pending());

        let (outcome, server) = tokio::join!(
            connection.reconnect(0),
            accept_connection(&session.server_endpoint, RECONNECT_TIMEOUT),
        );
        assert!(matches!(
            outcome.expect("reconnect with reload should succeed"),
            ReconnectOutcome::Reconnected
        ));
        server.expect("server handshake should succeed");
        assert_ne!(
            endpoint_addr,
            connection.endpoint_addr(),
            "endpoint should be rebuilt when reload was requested"
        );
        assert!(
            connection.reload_pending(),
            "local mode commits the reload only once a stream opens on it"
        );
        let _stream = open_log_only(&connection).await;
        assert!(
            !connection.reload_pending(),
            "the reload flag should be cleared after a successful rebuild"
        );
    }

    #[tokio::test]
    async fn reload_request_reaches_every_connection_owner() {
        let reload = ReloadSignal::new();
        let (first, first_session) = connect_test_connection(
            StreamErrorPolicy::ReopenStream,
            &reload,
            CancellationToken::new(),
        )
        .await
        .expect("first connection should be established");
        let (second, second_session) = connect_test_connection(
            StreamErrorPolicy::ReopenStream,
            &reload,
            CancellationToken::new(),
        )
        .await
        .expect("second connection should be established");
        let first_addr = first.endpoint_addr();
        let second_addr = second.endpoint_addr();

        reload.request();

        let (first_outcome, first_server) = tokio::join!(
            first.reconnect(0),
            accept_connection(&first_session.server_endpoint, RECONNECT_TIMEOUT),
        );
        first_outcome.expect("first reconnect should succeed");
        first_server.expect("first server handshake should succeed");
        assert_ne!(first_addr, first.endpoint_addr());
        assert!(!first.reload_pending());
        assert!(
            second.reload_pending(),
            "one owner's reconnect must not clear another owner's reload flag",
        );

        let (second_outcome, second_server) = tokio::join!(
            second.reconnect(0),
            accept_connection(&second_session.server_endpoint, RECONNECT_TIMEOUT),
        );
        second_outcome.expect("second reconnect should succeed");
        second_server.expect("second server handshake should succeed");
        assert_ne!(
            second_addr,
            second.endpoint_addr(),
            "every owner must reload its TLS material after one request",
        );
        assert!(!second.reload_pending());
    }

    /// The fix over 0.25.1: a `SIGHUP` that arrives while a reconnect is
    /// applying an earlier reload is not cleared by that reconnect.
    #[tokio::test]
    async fn reload_requested_during_a_reloading_reconnect_stays_pending() {
        let reload = ReloadSignal::new();
        let (connection, session) = connect_test_connection(
            StreamErrorPolicy::Reconnect,
            &reload,
            CancellationToken::new(),
        )
        .await
        .expect("connection should be established");
        let original_addr = connection.endpoint_addr();
        reload.request();

        let server_endpoint = session.server_endpoint.clone();
        let server_reload = reload.clone();
        let (outcome, server) = tokio::join!(connection.reconnect(0), async move {
            let incoming = timeout(RECONNECT_TIMEOUT, server_endpoint.accept())
                .await
                .context("server should see the reconnect")?
                .context("server endpoint should stay open")?;
            let conn = incoming.await.context("QUIC setup should complete")?;
            // The reconnect has read its TLS files by now.
            server_reload.request();
            server_handshake(&conn, REQUIRED_GIGANTO_VERSION).await?;
            Ok::<_, anyhow::Error>(conn)
        });
        assert!(matches!(
            outcome.expect("reconnect should succeed"),
            ReconnectOutcome::Reconnected
        ));
        server.expect("server handshake should succeed");
        let _stream = open_log_only(&connection).await;
        let reloaded_addr = connection.endpoint_addr();
        assert_ne!(
            original_addr, reloaded_addr,
            "the earlier reload is applied"
        );
        assert!(
            connection.reload_pending(),
            "a request after the TLS files were read must stay pending",
        );

        let (outcome, server) = tokio::join!(
            connection.reconnect(1),
            accept_connection(&session.server_endpoint, RECONNECT_TIMEOUT),
        );
        outcome.expect("next reconnect should succeed");
        server.expect("server handshake should succeed");
        let _stream = open_log_only(&connection).await;
        assert_ne!(
            reloaded_addr,
            connection.endpoint_addr(),
            "the pending request is applied at the next reconnect",
        );
        assert!(!connection.reload_pending());
    }

    #[tokio::test]
    async fn reload_requested_during_initial_connect_applies_at_first_reconnect() {
        let reload = ReloadSignal::new();
        let (server_endpoint, server_addr) =
            build_server_endpoint().expect("test server endpoint should be created");
        let server_reload = reload.clone();
        let (connection, server) = tokio::join!(
            GigantoConnection::connect(
                fixture_config(server_addr),
                StreamErrorPolicy::Reconnect,
                &reload,
                CancellationToken::new(),
            ),
            async {
                let incoming = timeout(TEST_TIMEOUT, server_endpoint.accept())
                    .await
                    .context("server should see the connect")?
                    .context("server endpoint should stay open")?;
                let conn = incoming.await.context("QUIC setup should complete")?;
                server_reload.request();
                server_handshake(&conn, REQUIRED_GIGANTO_VERSION).await?;
                Ok::<_, anyhow::Error>(conn)
            },
        );
        let connection = connection.expect("connection should be established");
        server.expect("server handshake should succeed");
        assert!(
            connection.reload_pending(),
            "a request during the initial connect must stay pending",
        );

        let initial_addr = connection.endpoint_addr();
        let (outcome, server) = tokio::join!(
            connection.reconnect(0),
            accept_connection(&server_endpoint, RECONNECT_TIMEOUT),
        );
        outcome.expect("first reconnect should succeed");
        server.expect("server handshake should succeed");
        let _stream = open_log_only(&connection).await;
        assert_ne!(initial_addr, connection.endpoint_addr());
        assert!(!connection.reload_pending());
    }

    #[tokio::test]
    async fn rebuild_failure_preserves_last_known_good_endpoint() {
        let dir = tempdir().expect("tempdir should be created");
        let (server_endpoint, server_addr) =
            build_server_endpoint().expect("test server endpoint should be created");
        let config = copied_fixture_config(dir.path(), server_addr);
        let reload = ReloadSignal::new();
        let (connection, server) = tokio::join!(
            GigantoConnection::connect(
                config.clone(),
                StreamErrorPolicy::Reconnect,
                &reload,
                CancellationToken::new(),
            ),
            accept_connection(&server_endpoint, TEST_TIMEOUT),
        );
        let connection = connection.expect("connection should be established");
        server.expect("server handshake should succeed");
        let endpoint_addr = connection.endpoint_addr();

        fs::remove_file(&config.cert).expect("certificate should be removed");
        reload.request();
        let result = build_endpoint(&config, "rebuild").await;
        assert!(result.is_err(), "rebuild should fail with missing files");
        assert_eq!(endpoint_addr, connection.endpoint_addr());
        assert!(connection.reload_pending());
    }

    #[tokio::test]
    async fn reconnect_with_failed_rebuild_preserves_endpoint_and_leaves_reload_pending() {
        let dir = tempdir().expect("tempdir should be created");
        let (server_endpoint, server_addr) =
            build_server_endpoint().expect("test server endpoint should be created");
        let config = copied_fixture_config(dir.path(), server_addr);
        let reload = ReloadSignal::new();
        let (connection, server) = tokio::join!(
            GigantoConnection::connect(
                config.clone(),
                StreamErrorPolicy::Reconnect,
                &reload,
                CancellationToken::new(),
            ),
            accept_connection(&server_endpoint, TEST_TIMEOUT),
        );
        let connection = connection.expect("connection should be established");
        server.expect("server handshake should succeed");
        let endpoint_addr = connection.endpoint_addr();

        // Simulate a TLS rotation race where the new files are not yet on
        // disk: reload is requested, but the files can't be read. The
        // reconnect must still succeed using the existing endpoint, and the
        // reload must remain pending so a later reconnect can retry it.
        fs::remove_file(&config.cert).expect("certificate should be removed");
        fs::remove_file(&config.key).expect("key should be removed");
        reload.request();

        let (outcome, server) = tokio::join!(
            connection.reconnect(0),
            accept_connection(&server_endpoint, RECONNECT_TIMEOUT),
        );
        let outcome = outcome.expect("reconnect must succeed with the preserved endpoint");
        server.expect("server handshake should succeed against preserved endpoint");
        match outcome {
            ReconnectOutcome::ReloadDeferred(error) => assert!(
                matches!(*error, SenderError::ReadIdentity { .. }),
                "unexpected deferred error: {error:?}"
            ),
            other => panic!("reconnect should report ReloadDeferred, got {other:?}"),
        }
        assert_eq!(
            endpoint_addr,
            connection.endpoint_addr(),
            "endpoint must be preserved when rebuild fails during reconnect"
        );
        assert!(
            connection.reload_pending(),
            "the reload must stay pending so the next reconnect retries rebuild"
        );
    }

    // Simulates a reload candidate whose endpoint rebuild succeeds and whose
    // QUIC/TLS transport handshake completes, but whose Giganto application
    // handshake fails. The reconnect must fall back to the last-known-good
    // endpoint and report `ReloadDeferred` so the daemon can keep running
    // while a later reconnect retries the reload.
    #[tokio::test]
    async fn reconnect_with_successful_rebuild_but_failed_app_handshake_preserves_state() {
        let reload = ReloadSignal::new();
        let (connection, session) = connect_test_connection(
            StreamErrorPolicy::Reconnect,
            &reload,
            CancellationToken::new(),
        )
        .await
        .expect("connection should be established");
        let endpoint_addr = connection.endpoint_addr();
        reload.request();

        let (reconnect_result, server_result) = tokio::join!(connection.reconnect(0), async {
            // First accept: the rebuilt reload candidate connects but
            // the test server rejects the application handshake.
            let incoming = timeout(RECONNECT_TIMEOUT, session.server_endpoint.accept())
                .await
                .context("test server should accept the reload candidate in time")?
                .context("test server endpoint should stay open while accepting")?;
            let candidate_connection = incoming
                .await
                .context("reload candidate should complete QUIC setup")?;
            let candidate_err = server_handshake(&candidate_connection, "0.0.1")
                .await
                .expect_err("server should reject the reload candidate version");
            drop(candidate_connection);

            // Second accept: the fallback to the last-known-good endpoint
            // connects and completes the handshake.
            let fallback_connection =
                accept_connection(&session.server_endpoint, RECONNECT_TIMEOUT).await?;
            Ok::<_, anyhow::Error>((candidate_err, fallback_connection))
        });

        server_result.expect("server reconnect task should complete");
        let outcome = reconnect_result
            .expect("reconnect must succeed via the last-known-good endpoint fallback");
        match outcome {
            ReconnectOutcome::ReloadDeferred(error)
                if matches!(*error, SenderError::Handshake(_)) => {}
            other => panic!("reconnect should report ReloadDeferred(Handshake), got {other:?}"),
        }
        assert_eq!(
            endpoint_addr,
            connection.endpoint_addr(),
            "endpoint must stay the last-known-good one when the rebuilt endpoint's handshake fails"
        );
        assert!(
            connection.reload_pending(),
            "the reload must stay pending so the next reconnect retries it"
        );
    }

    // As in 0.25.1, a reload candidate whose handshake succeeds but whose
    // stream cannot open in local mode falls back to the last-known-good
    // endpoint and leaves the reload pending, instead of ending the process.
    #[tokio::test]
    async fn local_reload_candidate_without_a_stream_falls_back_and_stays_pending() {
        let reload = ReloadSignal::new();
        let (connection, session) = connect_test_connection(
            StreamErrorPolicy::Reconnect,
            &reload,
            CancellationToken::new(),
        )
        .await
        .expect("connection should be established");
        let endpoint_addr = connection.endpoint_addr();
        reload.request();

        let (outcome, candidate) = tokio::join!(
            connection.reconnect(0),
            accept_connection(&session.server_endpoint, RECONNECT_TIMEOUT),
        );
        assert!(matches!(
            outcome.expect("the reload candidate should complete its handshake"),
            ReconnectOutcome::Reconnected
        ));
        assert_ne!(endpoint_addr, connection.endpoint_addr());

        // The server goes away after the candidate's handshake, before its
        // stream opens.
        let candidate = candidate.expect("server should accept the reload candidate");
        candidate.close(0u32.into(), b"server-gone");
        let Current::Live(conn, 1) = connection.current() else {
            panic!("the owner should hold the reload candidate's connection");
        };
        timeout(TEST_TIMEOUT, conn.closed())
            .await
            .expect("the client should see the server close in time");

        let (opened, fallback) = tokio::join!(
            connection.open_stream(CancellationToken::new(), AckDelivery::LogOnly),
            accept_connection(&session.server_endpoint, RECONNECT_TIMEOUT),
        );
        let (mut stream, _) = opened.expect("the stream should open via the fallback");
        let fallback = fallback.expect("the fallback should connect");
        stream
            .send_header(RawEventKind::Log)
            .await
            .expect("the header should be written on the fallback connection");
        accept_server_stream(&fallback)
            .await
            .expect("the stream should arrive on the fallback connection");
        assert_eq!(connection.generation(), 2);
        assert_eq!(stream.generation(), 2);
        assert_eq!(
            endpoint_addr,
            connection.endpoint_addr(),
            "the fallback must use the last-known-good endpoint",
        );
        assert!(
            connection.reload_pending(),
            "the reload must stay pending so the next reconnect retries it",
        );
    }
}
