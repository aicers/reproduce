//! One bidirectional stream on a shared Giganto connection.

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use giganto_client::{
    RawEventKind,
    frame::{RecvError, SendError, send_raw},
    ingest::{receive_ack_timestamp, send_record_header},
};
use quinn::{Connection, RecvStream, SendStream, VarInt, WriteError};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use super::{
    CHANNEL_CLOSE_MESSAGE, CHANNEL_CLOSE_TIMEOUT, CHANNEL_CLOSE_TIMESTAMP, ReconnectOutcome,
    SenderError,
    connection::{Current, GigantoConnection, Lease, StreamErrorPolicy},
};

/// The application error code a stream is reset with when it is abandoned
/// without a close marker.
const STREAM_RESET_CODE: u32 = 0;

/// Selects whether a stream hands its ACK timestamps to the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AckDelivery {
    /// ACKs are only logged, and nothing accumulates.
    LogOnly,

    /// Every ACK is logged and delivered, in order, through an
    /// [`AckReceiver`]; none is dropped.
    Deliver,
}

/// Receives the ACK timestamps of one [`GigantoStream`], in order: data
/// timestamps and the close ACK ([`CHANNEL_CLOSE_TIMESTAMP`]).
///
/// It follows the stream across reopens and reconnects: once a reopen or
/// reconnect returns, no ACK of the replaced stream is received any more.
/// Every ACK the stream received is available before its close returns.
#[derive(Debug)]
pub struct AckReceiver {
    acks: mpsc::UnboundedReceiver<(u64, i64)>,
    epoch: Arc<AtomicU64>,
}

impl AckReceiver {
    /// Waits for the next ACK timestamp of the current stream.
    ///
    /// Returns `None` once the [`GigantoStream`] is dropped and every ACK it
    /// received has been taken.
    pub async fn recv(&mut self) -> Option<i64> {
        loop {
            let (epoch, timestamp) = self.acks.recv().await?;
            if epoch >= self.epoch.load(Ordering::Acquire) {
                return Some(timestamp);
            }
        }
    }

    /// Returns the next ACK timestamp of the current stream if one has
    /// already arrived.
    pub fn try_recv(&mut self) -> Option<i64> {
        loop {
            let (epoch, timestamp) = self.acks.try_recv().ok()?;
            if epoch >= self.epoch.load(Ordering::Acquire) {
                return Some(timestamp);
            }
        }
    }
}

/// How a stream's close ended its wait for the close ACK.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloseAck {
    /// The close ACK arrived within [`CHANNEL_CLOSE_TIMEOUT`].
    Received,

    /// No close ACK arrived within [`CHANNEL_CLOSE_TIMEOUT`].
    TimedOut,

    /// The stream's token was cancelled while waiting.
    Cancelled,

    /// The ACK receiver ended, with the stream or the connection, before
    /// the close ACK arrived.
    ReceiverEnded,

    /// No close marker was sent: the stream carried no record header, or no
    /// stream was open.
    NotSent,
}

impl CloseAck {
    /// Returns whether the close ACK arrived in time.
    #[must_use]
    pub fn received(self) -> bool {
        self == Self::Received
    }
}

/// Sends one stream of raw events on a [`GigantoConnection`]: a record
/// header, batches and a close marker, receiving the server's ACKs.
///
/// Closing, aborting or reopening a stream never closes the connection.
#[derive(Debug)]
pub struct GigantoStream {
    connection: GigantoConnection,
    /// Ends the wait for the close ACK and stops the ACK receiver.
    token: CancellationToken,
    /// The generation of the connection the stream was last opened on.
    generation: u64,
    open: Option<OpenStream>,
    current_stream_kind: Option<RawEventKind>,
    /// Counts the streams opened, so ACKs of a replaced stream are dropped.
    epoch: u64,
    acks: Option<AckSink>,
    close_timeout: Duration,
}

#[derive(Debug)]
struct OpenStream {
    conn: Connection,
    send: SendStream,
    ack_task: AckTask,
    /// Resolves when the ACK receiver observes the channel-close ACK.
    close_ack: oneshot::Receiver<()>,
}

/// The ACK receiver task of one stream.
///
/// Dropping it cancels the task, so a stream dropped without a close, or a
/// close that is itself cancelled, leaves no ACK task running on a shared
/// connection.
#[derive(Debug)]
struct AckTask {
    token: CancellationToken,
    handle: Option<JoinHandle<std::result::Result<(), SenderError>>>,
}

impl AckTask {
    /// Cancels the task and waits for it, so no ACK task outlives its
    /// stream.
    async fn stop(mut self) {
        self.token.cancel();
        let Some(handle) = self.handle.take() else {
            return;
        };
        match handle.await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => warn!("ACK receiver task ended with error: {error}"),
            Err(error) => warn!("ACK receiver task join failed: {error}"),
        }
    }
}

impl Drop for AckTask {
    fn drop(&mut self) {
        self.token.cancel();
    }
}

/// Where an ACK receiver task delivers ACKs.
#[derive(Clone, Debug)]
struct AckSink {
    acks: mpsc::UnboundedSender<(u64, i64)>,
    /// The epoch of the stream whose ACKs the caller receives.
    current: Arc<AtomicU64>,
}

impl GigantoStream {
    pub(super) async fn open(
        connection: GigantoConnection,
        token: CancellationToken,
        delivery: AckDelivery,
    ) -> std::result::Result<(Self, Option<AckReceiver>), SenderError> {
        let (acks, receiver) = match delivery {
            AckDelivery::LogOnly => (None, None),
            AckDelivery::Deliver => {
                let (sender, receiver) = mpsc::unbounded_channel();
                let current = Arc::new(AtomicU64::new(0));
                (
                    Some(AckSink {
                        acks: sender,
                        current: Arc::clone(&current),
                    }),
                    Some(AckReceiver {
                        acks: receiver,
                        epoch: current,
                    }),
                )
            }
        };
        let generation = connection.generation();
        let mut stream = Self {
            connection,
            token,
            generation,
            open: None,
            current_stream_kind: None,
            epoch: 0,
            acks,
            close_timeout: CHANNEL_CLOSE_TIMEOUT,
        };
        stream.open_new(None).await?;
        Ok((stream, receiver))
    }

    /// Writes the record header for `protocol` to the stream, or returns
    /// immediately if the stream already carries that kind.
    ///
    /// Each transfer calls this before sending any batch, and again after
    /// the stream is reopened or reconnected. Deduplication ensures a single
    /// stream is not prefixed twice with a header for the same kind.
    ///
    /// # Errors
    ///
    /// Returns an error if writing the header to the QUIC stream fails, or
    /// a write error if no stream is open.
    pub async fn send_header(
        &mut self,
        protocol: RawEventKind,
    ) -> std::result::Result<(), SenderError> {
        if self.current_stream_kind == Some(protocol) {
            return Ok(());
        }
        let open = self.live_stream().map_err(SenderError::Send)?;
        send_record_header(&mut open.send, protocol)
            .await
            .map_err(SenderError::Send)?;
        self.current_stream_kind = Some(protocol);
        Ok(())
    }

    /// Sends a batch of `(timestamp, serialized_event)` pairs.
    ///
    /// # Errors
    ///
    /// Returns a `SendError` if serialization or writing to the stream fails,
    /// or a write error if no stream is open.
    pub async fn send_batch(&mut self, events: &[(i64, Vec<u8>)]) -> Result<(), SendError> {
        let open = self.live_stream()?;
        let buf = bincode::serialize(&events)?;
        send_raw(&mut open.send, &buf).await
    }

    /// Recovers from a write error according to the connection's
    /// [`StreamErrorPolicy`] and opens a new stream, which needs its record
    /// header again.
    ///
    /// With [`StreamErrorPolicy::Reconnect`], or when the connection is
    /// lost, asks the owner for a connection newer than the one the stream
    /// failed on. With [`StreamErrorPolicy::ReopenStream`] and a live
    /// connection, resets only this stream and opens a new one on the same
    /// connection.
    /// When no stream is open (after an abort, a close or a failed
    /// recovery), opens one as [`reopen`](Self::reopen) does.
    ///
    /// # Errors
    ///
    /// Returns an error when the reconnect fails or is cancelled, or the
    /// connection is closed.
    pub async fn recover(&mut self) -> std::result::Result<ReconnectOutcome, SenderError> {
        let Some(open) = &self.open else {
            // No stream failed on a connection; open one where it can be.
            return self.reopen().await;
        };
        let live = open.conn.close_reason().is_none();
        if live && self.connection.policy() == StreamErrorPolicy::ReopenStream {
            return self.reopen().await;
        }

        // Keep the failed stream until its connection is replaced: dropping
        // a send stream on a live connection would finish it gracefully.
        let failed = self.stop_open().await;
        let lease = self.connection.reconnect_lease(self.generation).await;
        drop(failed);
        let lease = lease?;
        let outcome = lease.outcome.clone();
        Ok(self.open_new(Some(lease)).await?.unwrap_or(outcome))
    }

    /// Resets the stream without a close marker and opens a new one on the
    /// current connection, which needs its record header again.
    ///
    /// If the connection is lost, asks the owner for a newer one first, as a
    /// write error does. Other streams and the connection are untouched.
    ///
    /// # Errors
    ///
    /// Returns an error when a needed reconnect fails or is cancelled, the
    /// connection is closed, or the stream's token is cancelled.
    pub async fn reopen(&mut self) -> std::result::Result<ReconnectOutcome, SenderError> {
        self.abort().await;
        Ok(self
            .open_new(None)
            .await?
            .unwrap_or(ReconnectOutcome::StreamReopened))
    }

    /// Resets the stream without a close marker. Other streams and the
    /// connection are untouched. A later [`reopen`](Self::reopen) or
    /// [`recover`](Self::recover) opens a new stream.
    pub async fn abort(&mut self) {
        if let Some(mut failed) = self.stop_open().await {
            let _ = failed.reset(VarInt::from_u32(STREAM_RESET_CODE));
        }
    }

    /// Closes the stream: sends the channel-close marker, waits for its ACK,
    /// and finishes the stream. Never closes the connection.
    ///
    /// The wait ends at the close ACK, at [`CHANNEL_CLOSE_TIMEOUT`], or when
    /// the stream's token is cancelled; the returned [`CloseAck`] says which.
    /// Every ACK the stream received is handed to the [`AckReceiver`] before
    /// this returns. When the stream carries no record header, the marker is
    /// skipped and the stream is finished directly.
    ///
    /// # Errors
    ///
    /// Returns an error if the channel-close message cannot be sent or the
    /// stream cannot be finished.
    pub async fn close(&mut self) -> std::result::Result<CloseAck, SenderError> {
        let Some(mut open) = self.open.take() else {
            self.current_stream_kind = None;
            return Ok(CloseAck::NotSent);
        };

        let close_ack = if self.current_stream_kind.take().is_some() {
            if let Err(error) = send_close_marker(&mut open.send).await {
                open.ack_task.stop().await;
                return Err(error);
            }
            self.wait_for_close_ack(open.close_ack).await
        } else {
            CloseAck::NotSent
        };

        let finished = open
            .send
            .finish()
            .map_err(|source| SenderError::context("failed to finish stream", source));
        open.ack_task.stop().await;
        finished?;
        Ok(close_ack)
    }

    /// Returns the generation of the connection the stream was last opened
    /// on.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns whether a stream is open.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.open.is_some()
    }

    fn live_stream(&mut self) -> Result<&mut OpenStream, SendError> {
        self.open
            .as_mut()
            .ok_or(SendError::WriteError(WriteError::ClosedStream))
    }

    /// Opens a new stream on `lease`, or on the current connection.
    ///
    /// A connection found lost before the open is replaced by a newer one.
    /// When opening fails, [`StreamErrorPolicy::ReopenStream`] asks for a
    /// newer connection and tries again, while
    /// [`StreamErrorPolicy::Reconnect`] returns the error, as local mode
    /// always has.
    ///
    /// Returns the outcome of the reconnect it needed, if any.
    async fn open_new(
        &mut self,
        lease: Option<Lease>,
    ) -> std::result::Result<Option<ReconnectOutcome>, SenderError> {
        let mut outcome = None;
        let (mut conn, mut generation) = match lease {
            Some(lease) => (lease.conn, lease.generation),
            None => match self.connection.current() {
                Current::Live(conn, generation) => (conn, generation),
                Current::Lost(generation) => {
                    let lease = self.connection.reconnect_lease(generation).await?;
                    outcome = Some(lease.outcome);
                    (lease.conn, lease.generation)
                }
                Current::Closed => return Err(SenderError::Closed),
            },
        };

        loop {
            let opened = tokio::select! {
                opened = conn.open_bi() => opened,
                () = self.token.cancelled() => return Err(SenderError::Cancelled),
            };
            match opened {
                Ok((send, recv)) => {
                    self.install(conn, generation, send, recv);
                    return Ok(outcome);
                }
                Err(error) if self.connection.policy() == StreamErrorPolicy::Reconnect => {
                    // Local mode gives up when a stream cannot open on a
                    // connection that has just completed its handshake.
                    return Err(SenderError::context(
                        "failed to open stream to Giganto",
                        error,
                    ));
                }
                Err(error) => {
                    warn!("Failed to open stream to Giganto, reconnecting: {error}");
                    let lease = self.connection.reconnect_lease(generation).await?;
                    outcome = Some(lease.outcome);
                    conn = lease.conn;
                    generation = lease.generation;
                }
            }
        }
    }

    fn install(&mut self, conn: Connection, generation: u64, send: SendStream, recv: RecvStream) {
        self.epoch += 1;
        let (close_ack_tx, close_ack) = oneshot::channel();
        let ack_task_token = self.token.child_token();
        let sink = self.acks.clone();
        let epoch = self.epoch;
        let ack_task_handle = tokio::spawn(recv_ack(
            recv,
            close_ack_tx,
            sink.map(|sink| (sink.acks, epoch)),
            ack_task_token.clone(),
        ));
        if let Some(sink) = &self.acks {
            sink.current.store(epoch, Ordering::Release);
        }
        self.generation = generation;
        self.current_stream_kind = None;
        self.open = Some(OpenStream {
            conn,
            send,
            ack_task: AckTask {
                token: ack_task_token,
                handle: Some(ack_task_handle),
            },
            close_ack,
        });
    }

    /// Stops the open stream's ACK receiver and returns its send stream.
    async fn stop_open(&mut self) -> Option<SendStream> {
        self.current_stream_kind = None;
        let open = self.open.take()?;
        open.ack_task.stop().await;
        Some(open.send)
    }

    async fn wait_for_close_ack(&self, close_ack: oneshot::Receiver<()>) -> CloseAck {
        // The ACK receiver stops on the same token, so cancellation is
        // checked first to report it rather than the receiver's end.
        tokio::select! {
            biased;
            () = self.token.cancelled() => {
                warn!("Shutdown requested while waiting for channel-close ACK");
                CloseAck::Cancelled
            }
            result = close_ack => {
                if result.is_ok() {
                    CloseAck::Received
                } else {
                    warn!("ACK receiver ended before channel-close ACK was delivered");
                    CloseAck::ReceiverEnded
                }
            }
            () = tokio::time::sleep(self.close_timeout) => {
                warn!("Timed out waiting for channel-close ACK");
                CloseAck::TimedOut
            }
        }
    }

    #[cfg(test)]
    pub(super) fn current_stream_kind(&self) -> Option<RawEventKind> {
        self.current_stream_kind
    }

    #[cfg(test)]
    pub(super) fn set_current_stream_kind(&mut self, kind: Option<RawEventKind>) {
        self.current_stream_kind = kind;
    }

    #[cfg(test)]
    pub(super) fn set_close_timeout(&mut self, close_timeout: Duration) {
        self.close_timeout = close_timeout;
    }

    #[cfg(test)]
    pub(super) fn close_timeout(&self) -> Duration {
        self.close_timeout
    }

    #[cfg(test)]
    pub(super) fn ack_task_token(&self) -> Option<CancellationToken> {
        self.open.as_ref().map(|open| open.ack_task.token.clone())
    }
}

/// Sends the channel-close sentinel message to signal the server that no
/// more events will follow.
async fn send_close_marker(send: &mut SendStream) -> std::result::Result<(), SenderError> {
    let record_data = bincode::serialize(CHANNEL_CLOSE_MESSAGE)
        .map_err(|error| SenderError::Send(error.into()))?;
    let events = vec![(CHANNEL_CLOSE_TIMESTAMP, record_data)];
    let buf = bincode::serialize(&events).map_err(|error| SenderError::Send(error.into()))?;
    match send_raw(send, &buf).await {
        Err(SendError::WriteError(_)) => Err(SenderError::SendFinish),
        Err(e) => Err(SenderError::Send(e)),
        Ok(()) => Ok(()),
    }
}

/// Receives acknowledgement timestamps from the server, logs them, and hands
/// them to `acks` when the caller receives ACKs. The task notifies the close
/// when the channel-close sentinel is echoed back, after handing it on, and
/// exits promptly when `token` is cancelled.
async fn recv_ack(
    mut recv: RecvStream,
    close_ack: oneshot::Sender<()>,
    acks: Option<(mpsc::UnboundedSender<(u64, i64)>, u64)>,
    token: CancellationToken,
) -> std::result::Result<(), SenderError> {
    let mut close_ack = Some(close_ack);
    loop {
        let timestamp = tokio::select! {
            result = receive_ack_timestamp(&mut recv) => result,
            () = token.cancelled() => break,
        };
        match timestamp {
            Ok(timestamp) => {
                if timestamp == CHANNEL_CLOSE_TIMESTAMP {
                    info!("Finish ACK: {timestamp}");
                } else {
                    info!("ACK: {timestamp}");
                }
                if let Some((acks, epoch)) = &acks {
                    let _ = acks.send((*epoch, timestamp));
                }
                if timestamp == CHANNEL_CLOSE_TIMESTAMP
                    && let Some(close_ack) = close_ack.take()
                {
                    let _ = close_ack.send(());
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
    use anyhow::{Context, Result};
    use giganto_client::ingest::receive_record_header;
    use quinn::{Endpoint, ReadError};
    use tokio::time::{Duration, timeout};

    use super::super::test_support::{
        TEST_CERT_PEM, TEST_KEY_PEM, TEST_ROOT_PEM, TEST_SERVER_NAME, TEST_TIMEOUT,
        accept_server_stream, build_server_endpoint, connect_test_connection, connects_from,
        fixture_path, is_close_marker, recv_batch,
    };
    use super::super::{StreamErrorPolicy, create_endpoint};
    use super::*;
    use crate::reload::ReloadSignal;

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

    /// One stream as the test server sees it.
    struct ServerStream {
        send: SendStream,
        recv: RecvStream,
    }

    impl ServerStream {
        async fn accept(connection: &Connection, kind: RawEventKind) -> Result<Self> {
            let (send, mut recv) = accept_server_stream(connection).await?;
            let mut header = [0_u8; 4];
            receive_record_header(&mut recv, &mut header)
                .await
                .context("server should receive the record header")?;
            anyhow::ensure!(
                header == u32::from(kind).to_le_bytes(),
                "unexpected record header"
            );
            Ok(Self { send, recv })
        }

        async fn ack(&mut self, timestamp: i64) {
            self.send
                .write_all(&timestamp.to_be_bytes())
                .await
                .expect("server should send the ACK");
        }
    }

    /// Connects, opens two streams with their headers sent, and accepts
    /// both on the server.
    async fn two_streams(
        delivery: AckDelivery,
    ) -> (
        GigantoConnection,
        super::super::test_support::ServerSession,
        [(GigantoStream, Option<AckReceiver>, ServerStream); 2],
    ) {
        let reload = ReloadSignal::new();
        let (connection, session) = connect_test_connection(
            StreamErrorPolicy::ReopenStream,
            &reload,
            CancellationToken::new(),
        )
        .await
        .expect("connection should be established");
        let mut opened = Vec::new();
        for kind in [RawEventKind::Log, RawEventKind::Dns] {
            let (mut stream, acks) = connection
                .open_stream(CancellationToken::new(), delivery)
                .await
                .expect("stream should open");
            stream
                .send_header(kind)
                .await
                .expect("header should be sent");
            let server = ServerStream::accept(&session.connection, kind)
                .await
                .expect("server should accept the stream");
            opened.push((stream, acks, server));
        }
        let second = opened.pop().expect("two streams were opened");
        let first = opened.pop().expect("two streams were opened");
        (connection, session, [first, second])
    }

    async fn next_ack(acks: &mut AckReceiver) -> i64 {
        timeout(TEST_TIMEOUT, acks.recv())
            .await
            .expect("an ACK should be delivered in time")
            .expect("the ACK receiver should stay open")
    }

    #[tokio::test]
    async fn recv_ack_notifies_on_close_ack() {
        let mut channel = open_ack_channel()
            .await
            .expect("raw ACK channel should be established");
        let token = CancellationToken::new();
        let (close_ack_tx, close_ack) = oneshot::channel();
        let recv_handle = tokio::spawn(recv_ack(
            channel.client_recv,
            close_ack_tx,
            None,
            token.clone(),
        ));

        channel
            .server_send
            .write_all(&CHANNEL_CLOSE_TIMESTAMP.to_be_bytes())
            .await
            .expect("server should send the close ACK timestamp");
        close_ack
            .await
            .expect("recv_ack should notify close ACK completion");

        token.cancel();
        recv_handle
            .await
            .expect("recv_ack task should join cleanly")
            .expect("recv_ack should stop cleanly after cancellation");
    }

    #[tokio::test]
    async fn recv_ack_does_not_notify_for_regular_ack() {
        let mut channel = open_ack_channel()
            .await
            .expect("raw ACK channel should be established");
        let token = CancellationToken::new();
        let (close_ack_tx, close_ack) = oneshot::channel();
        let recv_handle = tokio::spawn(recv_ack(
            channel.client_recv,
            close_ack_tx,
            None,
            token.clone(),
        ));

        channel
            .server_send
            .write_all(&123_i64.to_be_bytes())
            .await
            .expect("server should send a regular ACK timestamp");
        assert!(
            timeout(Duration::from_millis(100), close_ack)
                .await
                .is_err(),
            "regular ACKs must not notify channel-close completion",
        );
        channel
            .server_send
            .finish()
            .expect("server should finish the ACK stream");

        recv_handle
            .await
            .expect("recv_ack task should join cleanly")
            .expect("recv_ack should return success after stream close");
    }

    #[tokio::test]
    async fn recv_ack_exits_promptly_on_cancellation() {
        let channel = open_ack_channel()
            .await
            .expect("raw ACK channel should be established");
        let token = CancellationToken::new();
        let (close_ack_tx, _close_ack) = oneshot::channel();
        let recv_handle = tokio::spawn(recv_ack(
            channel.client_recv,
            close_ack_tx,
            None,
            token.clone(),
        ));

        token.cancel();
        timeout(Duration::from_millis(200), recv_handle)
            .await
            .expect("ACK receiver should exit promptly on cancellation")
            .expect("recv_ack task should join cleanly")
            .expect("recv_ack cancellation should be clean");
    }

    #[tokio::test]
    async fn recv_ack_hands_every_ack_on_in_order_before_the_close_notice() {
        let mut channel = open_ack_channel()
            .await
            .expect("raw ACK channel should be established");
        let token = CancellationToken::new();
        let (close_ack_tx, close_ack) = oneshot::channel();
        let (acks_tx, mut acks_rx) = mpsc::unbounded_channel();
        let recv_handle = tokio::spawn(recv_ack(
            channel.client_recv,
            close_ack_tx,
            Some((acks_tx, 3)),
            token.clone(),
        ));

        for timestamp in [10_i64, 11, 12, CHANNEL_CLOSE_TIMESTAMP] {
            channel
                .server_send
                .write_all(&timestamp.to_be_bytes())
                .await
                .expect("server should send the ACK");
        }
        close_ack.await.expect("close ACK should be notified");
        let mut received = Vec::new();
        while let Ok(ack) = acks_rx.try_recv() {
            received.push(ack);
        }
        assert_eq!(
            received,
            vec![(3, 10), (3, 11), (3, 12), (3, CHANNEL_CLOSE_TIMESTAMP)],
            "every ACK must be handed on, in order, before the close notice",
        );
        token.cancel();
        recv_handle
            .await
            .expect("recv_ack task should join cleanly")
            .expect("recv_ack should stop cleanly");
    }

    #[tokio::test]
    async fn log_only_streams_have_no_ack_receiver() {
        let reload = ReloadSignal::new();
        let (connection, _session) = connect_test_connection(
            StreamErrorPolicy::Reconnect,
            &reload,
            CancellationToken::new(),
        )
        .await
        .expect("connection should be established");
        let (_stream, acks) = connection
            .open_stream(CancellationToken::new(), AckDelivery::LogOnly)
            .await
            .expect("stream should open");
        assert!(acks.is_none());
    }

    #[tokio::test]
    async fn two_streams_send_concurrently_on_one_connection() {
        let (
            connection,
            session,
            [
                (mut first, _, mut first_server),
                (mut second, _, mut second_server),
            ],
        ) = two_streams(AckDelivery::LogOnly).await;

        let first_batch = [(1, b"first".to_vec())];
        let second_batch = [(2, b"second".to_vec())];
        let (first_sent, second_sent) = tokio::join!(
            first.send_batch(&first_batch),
            second.send_batch(&second_batch),
        );
        first_sent.expect("first stream should send");
        second_sent.expect("second stream should send");
        assert_eq!(
            recv_batch(&mut first_server.recv)
                .await
                .expect("first batch should arrive"),
            vec![(1, b"first".to_vec())]
        );
        assert_eq!(
            recv_batch(&mut second_server.recv)
                .await
                .expect("second batch should arrive"),
            vec![(2, b"second".to_vec())]
        );

        let first_close = tokio::spawn(async move {
            let close = first.close().await;
            (first, close)
        });
        let marker = recv_batch(&mut first_server.recv)
            .await
            .expect("first close marker should arrive");
        assert!(is_close_marker(&marker));
        first_server.ack(CHANNEL_CLOSE_TIMESTAMP).await;
        let (_first, close) = first_close.await.expect("close task should join");
        assert_eq!(
            close.expect("first close should succeed"),
            CloseAck::Received
        );

        second
            .send_batch(&[(3, b"after".to_vec())])
            .await
            .expect("closing one stream leaves the other sending");
        assert_eq!(
            recv_batch(&mut second_server.recv)
                .await
                .expect("batch after the other close should arrive"),
            vec![(3, b"after".to_vec())]
        );
        assert_eq!(second.generation(), 0);
        assert_eq!(connection.generation(), 0);
        assert!(session.connection.close_reason().is_none());
    }

    #[tokio::test]
    async fn close_delivers_every_ack_and_reports_the_close_ack() {
        let (_connection, _session, [(mut stream, acks, mut server), _]) =
            two_streams(AckDelivery::Deliver).await;
        let mut acks = acks.expect("delivering streams have an ACK receiver");

        stream
            .send_batch(&[(41, b"a".to_vec()), (42, b"b".to_vec())])
            .await
            .expect("batch should be sent");
        recv_batch(&mut server.recv)
            .await
            .expect("batch should arrive");
        server.ack(42).await;
        assert_eq!(next_ack(&mut acks).await, 42);

        stream
            .send_batch(&[(43, b"c".to_vec())])
            .await
            .expect("batch should be sent");
        recv_batch(&mut server.recv)
            .await
            .expect("batch should arrive");
        let close = tokio::spawn(async move {
            let close = stream.close().await;
            (stream, close)
        });
        let marker = recv_batch(&mut server.recv)
            .await
            .expect("close marker should arrive");
        assert!(is_close_marker(&marker));
        server.ack(43).await;
        server.ack(CHANNEL_CLOSE_TIMESTAMP).await;
        let (_stream, close) = close.await.expect("close task should join");
        let close = close.expect("close should succeed");
        assert_eq!(close, CloseAck::Received);
        assert!(close.received());

        // Every ACK is handed over before the close returns.
        assert_eq!(acks.try_recv(), Some(43));
        assert_eq!(acks.try_recv(), Some(CHANNEL_CLOSE_TIMESTAMP));
        assert_eq!(acks.try_recv(), None);
    }

    #[tokio::test]
    async fn close_reports_a_missing_close_ack() {
        let (_connection, _session, [(mut stream, acks, mut server), _]) =
            two_streams(AckDelivery::Deliver).await;
        let mut acks = acks.expect("delivering streams have an ACK receiver");
        assert_eq!(stream.close_timeout(), CHANNEL_CLOSE_TIMEOUT);
        stream.set_close_timeout(Duration::from_millis(300));

        let close = tokio::spawn(async move { stream.close().await });
        let marker = recv_batch(&mut server.recv)
            .await
            .expect("close marker should arrive");
        assert!(is_close_marker(&marker));
        server.ack(7).await;
        let close = timeout(TEST_TIMEOUT, close)
            .await
            .expect("close should end at its timeout")
            .expect("close task should join")
            .expect("close should succeed");
        assert_eq!(close, CloseAck::TimedOut);
        assert!(!close.received());
        assert_eq!(acks.try_recv(), Some(7));
    }

    #[tokio::test]
    async fn close_waits_past_a_cancelled_connect_token() {
        let reload = ReloadSignal::new();
        let connect_token = CancellationToken::new();
        let (connection, session) = connect_test_connection(
            StreamErrorPolicy::ReopenStream,
            &reload,
            connect_token.clone(),
        )
        .await
        .expect("connection should be established");
        let (mut stream, _) = connection
            .open_stream(CancellationToken::new(), AckDelivery::LogOnly)
            .await
            .expect("stream should open");
        stream
            .send_header(RawEventKind::Log)
            .await
            .expect("header should be sent");
        let mut server = ServerStream::accept(&session.connection, RawEventKind::Log)
            .await
            .expect("server should accept the stream");

        let close = tokio::spawn(async move { stream.close().await });
        let marker = recv_batch(&mut server.recv)
            .await
            .expect("close marker should arrive");
        assert!(is_close_marker(&marker));
        connect_token.cancel();
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(
            !close.is_finished(),
            "cancelling the connect token must not end a stream's close wait",
        );
        server.ack(CHANNEL_CLOSE_TIMESTAMP).await;
        let close = timeout(TEST_TIMEOUT, close)
            .await
            .expect("close should end at the close ACK")
            .expect("close task should join")
            .expect("close should succeed");
        assert_eq!(close, CloseAck::Received);
    }

    #[tokio::test]
    async fn close_wait_ends_at_once_when_the_stream_token_is_cancelled() {
        let reload = ReloadSignal::new();
        let token = CancellationToken::new();
        // Local mode passes its shutdown token as both tokens.
        let (connection, session) =
            connect_test_connection(StreamErrorPolicy::Reconnect, &reload, token.clone())
                .await
                .expect("connection should be established");
        let (mut stream, _) = connection
            .open_stream(token.clone(), AckDelivery::LogOnly)
            .await
            .expect("stream should open");
        stream
            .send_header(RawEventKind::Log)
            .await
            .expect("header should be sent");
        let mut server = ServerStream::accept(&session.connection, RawEventKind::Log)
            .await
            .expect("server should accept the stream");

        let close = tokio::spawn(async move { stream.close().await });
        let marker = recv_batch(&mut server.recv)
            .await
            .expect("close marker should arrive");
        assert!(is_close_marker(&marker));
        token.cancel();
        let close = timeout(Duration::from_secs(1), close)
            .await
            .expect("cancelling the stream token must end the wait at once")
            .expect("close task should join")
            .expect("close should succeed");
        assert_eq!(close, CloseAck::Cancelled);
    }

    #[tokio::test]
    async fn abort_resets_one_stream_without_a_close_marker() {
        let (
            connection,
            session,
            [
                (mut aborted, _, mut aborted_server),
                (mut other, _, mut other_server),
            ],
        ) = two_streams(AckDelivery::LogOnly).await;

        aborted.abort().await;
        assert!(!aborted.is_open());
        let mut buf = [0_u8; 64];
        let read = timeout(TEST_TIMEOUT, aborted_server.recv.read(&mut buf))
            .await
            .expect("server should see the reset in time");
        assert!(
            matches!(read, Err(ReadError::Reset(_))),
            "an aborted stream must be reset without a close marker, got {read:?}",
        );

        other
            .send_batch(&[(9, b"other".to_vec())])
            .await
            .expect("the other stream keeps sending");
        assert_eq!(
            recv_batch(&mut other_server.recv)
                .await
                .expect("the other batch should arrive"),
            vec![(9, b"other".to_vec())]
        );
        assert_eq!(connection.generation(), 0);
        assert!(session.connection.close_reason().is_none());
    }

    #[tokio::test]
    async fn reopen_on_request_resets_and_opens_a_new_stream() {
        let (
            connection,
            session,
            [
                (mut reopened, _, mut old_server),
                (mut other, _, mut other_server),
            ],
        ) = two_streams(AckDelivery::LogOnly).await;

        let outcome = reopened
            .reopen()
            .await
            .expect("reopen should open a new stream");
        assert!(matches!(outcome, ReconnectOutcome::StreamReopened));
        let mut buf = [0_u8; 64];
        let read = timeout(TEST_TIMEOUT, old_server.recv.read(&mut buf))
            .await
            .expect("server should see the reset in time");
        assert!(
            matches!(read, Err(ReadError::Reset(_))),
            "a reopened stream must be reset without a close marker, got {read:?}",
        );

        reopened
            .send_header(RawEventKind::Log)
            .await
            .expect("the new stream needs its header again");
        reopened
            .send_batch(&[(5, b"new".to_vec())])
            .await
            .expect("the new stream should send");
        let mut new_server = ServerStream::accept(&session.connection, RawEventKind::Log)
            .await
            .expect("the new stream should arrive on the same connection");
        assert_eq!(
            recv_batch(&mut new_server.recv)
                .await
                .expect("the new stream's batch should arrive"),
            vec![(5, b"new".to_vec())]
        );

        other
            .send_batch(&[(6, b"other".to_vec())])
            .await
            .expect("the other stream keeps sending");
        assert_eq!(
            recv_batch(&mut other_server.recv)
                .await
                .expect("the other batch should arrive"),
            vec![(6, b"other".to_vec())]
        );
        assert_eq!(connection.generation(), 0);
        assert!(session.connection.close_reason().is_none());
    }

    #[tokio::test]
    async fn no_ack_of_a_replaced_stream_is_delivered_after_reopen() {
        let (_connection, session, [(mut stream, acks, mut old_server), _]) =
            two_streams(AckDelivery::Deliver).await;
        let mut acks = acks.expect("delivering streams have an ACK receiver");

        old_server.ack(1).await;
        assert_eq!(next_ack(&mut acks).await, 1);
        // This ACK reaches the old stream's receiver, but the caller has not
        // taken it before the stream is replaced.
        old_server.ack(100).await;
        tokio::time::sleep(Duration::from_millis(200)).await;

        stream.reopen().await.expect("reopen should succeed");
        stream
            .send_header(RawEventKind::Log)
            .await
            .expect("the new stream needs its header again");
        let mut new_server = ServerStream::accept(&session.connection, RawEventKind::Log)
            .await
            .expect("the new stream should arrive");
        new_server.ack(200).await;
        assert_eq!(
            next_ack(&mut acks).await,
            200,
            "no ACK of the replaced stream may be delivered after reopen returns",
        );
    }

    #[tokio::test]
    async fn sends_on_an_aborted_stream_fail_until_it_is_reopened() {
        let (_connection, _session, [(mut stream, _, _server), _]) =
            two_streams(AckDelivery::LogOnly).await;
        stream.abort().await;
        assert!(matches!(
            stream.send_batch(&[(1, b"x".to_vec())]).await,
            Err(SendError::WriteError(WriteError::ClosedStream))
        ));
        assert!(matches!(
            stream.send_header(RawEventKind::Log).await,
            Err(SenderError::Send(SendError::WriteError(
                WriteError::ClosedStream
            )))
        ));
        assert_eq!(
            stream
                .close()
                .await
                .expect("closing an aborted stream is a no-op"),
            CloseAck::NotSent
        );
        let outcome = stream
            .recover()
            .await
            .expect("recover opens a new stream on the live connection");
        assert!(matches!(outcome, ReconnectOutcome::StreamReopened));
        assert!(stream.is_open());
    }

    #[tokio::test]
    async fn local_stream_open_on_a_lost_connection_fails_without_reconnecting() {
        let reload = ReloadSignal::new();
        let (connection, session) = connect_test_connection(
            StreamErrorPolicy::Reconnect,
            &reload,
            CancellationToken::new(),
        )
        .await
        .expect("connection should be established");
        // The server goes away after the handshake, before the stream opens.
        session.connection.close(0u32.into(), b"server-gone");
        let Current::Live(conn, _) = connection.current() else {
            panic!("the owner should still hold the connection it handshook");
        };
        timeout(TEST_TIMEOUT, conn.closed())
            .await
            .expect("the client should see the server close in time");

        let client = session.connection.remote_address();
        let (opened, reconnected) = tokio::join!(
            connection.open_stream(CancellationToken::new(), AckDelivery::LogOnly),
            connects_from(&session.server_endpoint, client, Duration::from_secs(3)),
        );
        let error = opened.expect_err("local mode must not retry a failed stream open");
        assert!(
            matches!(
                &error,
                SenderError::Context { context, .. } if *context == "failed to open stream to Giganto"
            ),
            "unexpected stream open error: {error:?}",
        );
        assert!(
            !reconnected,
            "local mode must not reconnect to open a stream"
        );
        assert_eq!(connection.generation(), 0);
    }

    #[tokio::test]
    async fn dropping_a_stream_stops_its_ack_task() {
        let (
            connection,
            session,
            [
                (dropped, dropped_acks, _dropped_server),
                (mut other, _, mut other_server),
            ],
        ) = two_streams(AckDelivery::Deliver).await;
        let mut dropped_acks = dropped_acks.expect("delivering streams have an ACK receiver");
        let ack_task = dropped
            .ack_task_token()
            .expect("an open stream has an ACK task");

        // The server keeps the dropped stream's ACK side open.
        drop(dropped);
        assert!(ack_task.is_cancelled());
        assert_eq!(
            timeout(TEST_TIMEOUT, dropped_acks.recv())
                .await
                .expect("the ACK receiver should end once its stream is dropped"),
            None
        );

        other
            .send_batch(&[(8, b"other".to_vec())])
            .await
            .expect("the other stream keeps sending");
        assert_eq!(
            recv_batch(&mut other_server.recv)
                .await
                .expect("the other batch should arrive"),
            vec![(8, b"other".to_vec())]
        );
        assert_eq!(connection.generation(), 0);
        assert!(session.connection.close_reason().is_none());
    }

    #[tokio::test]
    async fn cancelled_close_stops_its_ack_task() {
        let (
            connection,
            session,
            [
                (mut closing, acks, mut server),
                (mut other, _, mut other_server),
            ],
        ) = two_streams(AckDelivery::Deliver).await;
        let mut acks = acks.expect("delivering streams have an ACK receiver");
        let ack_task = closing
            .ack_task_token()
            .expect("an open stream has an ACK task");

        // The server never sends the close ACK, and the caller stops waiting.
        let (close, marker) = tokio::join!(
            timeout(Duration::from_millis(300), closing.close()),
            recv_batch(&mut server.recv),
        );
        assert!(is_close_marker(
            &marker.expect("close marker should arrive")
        ));
        assert!(close.is_err(), "the close should still be waiting");
        assert!(!closing.is_open());
        assert!(ack_task.is_cancelled());

        drop(closing);
        assert_eq!(
            timeout(TEST_TIMEOUT, acks.recv())
                .await
                .expect("the ACK receiver should end once its stream is dropped"),
            None
        );
        other
            .send_batch(&[(9, b"other".to_vec())])
            .await
            .expect("the other stream keeps sending");
        assert_eq!(
            recv_batch(&mut other_server.recv)
                .await
                .expect("the other batch should arrive"),
            vec![(9, b"other".to_vec())]
        );
        assert_eq!(connection.generation(), 0);
        assert!(session.connection.close_reason().is_none());
    }
}
