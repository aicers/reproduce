use async_trait::async_trait;
use giganto_client::{RawEventKind, frame::SendError};
use thiserror::Error;
use tokio::sync::watch;
use tracing::warn;

use crate::collector::{Collector, CollectorError};
use crate::sender::{GigantoSender, ReconnectOutcome, SenderError};

#[derive(Debug, Error)]
pub enum PipelineError {
    #[error(transparent)]
    Collect(#[from] CollectorError),

    #[error(transparent)]
    Sender(#[from] SenderError),

    #[error("{0:?}")]
    Send(SendError),
}

/// Defines the sender operations required by the common pipeline.
#[async_trait]
pub trait PipelineSender {
    async fn send_header(&mut self, protocol: RawEventKind)
    -> std::result::Result<(), SenderError>;
    async fn send_batch(&mut self, events: &[(i64, Vec<u8>)])
    -> std::result::Result<(), SendError>;
    async fn reconnect(&mut self) -> std::result::Result<ReconnectOutcome, SenderError>;
}

#[async_trait]
impl PipelineSender for GigantoSender {
    async fn send_header(
        &mut self,
        protocol: RawEventKind,
    ) -> std::result::Result<(), SenderError> {
        GigantoSender::send_header(self, protocol).await
    }

    async fn send_batch(
        &mut self,
        events: &[(i64, Vec<u8>)],
    ) -> std::result::Result<(), SendError> {
        GigantoSender::send_batch(self, events).await
    }

    async fn reconnect(&mut self) -> std::result::Result<ReconnectOutcome, SenderError> {
        GigantoSender::reconnect(self).await
    }
}

/// Runs one collector to completion using any compatible sender.
///
/// `on_record_bytes` is called once per record with the raw byte size used by
/// the binary-level report implementation.
///
/// # Errors
///
/// Returns an error if the collector, sender, or reconnection logic fails.
pub async fn run_pipeline_with_sender<S, F>(
    sender: &mut S,
    collector: &mut dyn Collector,
    shutdown: watch::Receiver<bool>,
    on_record_bytes: &mut F,
) -> std::result::Result<(), PipelineError>
where
    S: PipelineSender + ?Sized,
    F: FnMut(usize) + ?Sized,
{
    // Emit the stream header before any batch so every transfer starts with a
    // raw event kind, even when the collector yields nothing.
    let kind = collector.kind();
    if !ensure_header_with_reconnect(sender, kind, &shutdown).await? {
        return Ok(());
    }

    while let Some(batch) = collector.next_batch().await? {
        for &bytes in &batch.record_bytes {
            on_record_bytes(bytes);
        }

        let mut shutdown_requested = false;

        loop {
            if *shutdown.borrow() {
                shutdown_requested = true;
                break;
            }
            match sender.send_batch(&batch.events).await {
                Ok(()) => break,
                Err(SendError::WriteError(_)) => {
                    log_reconnect_outcome(sender.reconnect().await?);
                    if !ensure_header_with_reconnect(sender, kind, &shutdown).await? {
                        // Shutdown requested while retrying the header on a
                        // fresh post-reconnect stream — the stream lacks a
                        // header, so no batch can safely be flushed.
                        return Ok(());
                    }
                }
                Err(error) => return Err(PipelineError::Send(error)),
            }
        }

        if shutdown_requested {
            // The header has already been written on the current stream —
            // either by the pre-pipeline send or by the post-reconnect send
            // inside the inner loop — so the shutdown flush only needs to
            // emit the pending batch.
            match sender.send_batch(&batch.events).await {
                Ok(()) => {}
                Err(error) => return Err(PipelineError::Send(error)),
            }
        }
    }

    Ok(())
}

// A broken stream may surface first as a header write failure rather than a
// batch write failure, so header sends use the same reconnect-and-retry path
// that batches do.
//
// Returns `Ok(true)` once the header has been written, `Ok(false)` if the
// shutdown signal is observed after a header write failure — callers must
// treat the latter as "no header on the current stream" and stop the pipeline
// rather than flushing batches that would arrive without a raw event kind.
// The shutdown check sits after the reconnect so a header send that succeeds
// despite an in-flight shutdown still completes; without that, the pipeline
// could loop forever when the receiver is unreachable, since header writes
// keep failing while reconnect keeps succeeding.
async fn ensure_header_with_reconnect<S>(
    sender: &mut S,
    kind: RawEventKind,
    shutdown: &watch::Receiver<bool>,
) -> std::result::Result<bool, PipelineError>
where
    S: PipelineSender + ?Sized,
{
    loop {
        match sender.send_header(kind).await {
            Ok(()) => return Ok(true),
            Err(SenderError::Send(SendError::WriteError(_))) => {
                log_reconnect_outcome(sender.reconnect().await?);
                if *shutdown.borrow() {
                    return Ok(false);
                }
            }
            Err(error) => return Err(PipelineError::Sender(error)),
        }
    }
}

fn log_reconnect_outcome(outcome: ReconnectOutcome) {
    if let ReconnectOutcome::ReloadDeferred(error) = outcome {
        warn!(
            "QUIC endpoint reload deferred; \
             reconnected via last-known-good endpoint and \
             reload intent remains pending: {error}"
        );
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use async_trait::async_trait;
    use giganto_client::RawEventKind;
    use quinn::{VarInt, WriteError};
    use tokio::sync::watch;

    use super::*;
    use crate::collector::{CollectedBatch, Collector, CollectorResult};

    struct OneBatchCollector {
        yielded: bool,
        pos: Vec<u8>,
        next_pos: Vec<u8>,
    }

    #[async_trait]
    impl Collector for OneBatchCollector {
        fn kind(&self) -> RawEventKind {
            RawEventKind::Log
        }

        async fn next_batch(&mut self) -> CollectorResult<Option<CollectedBatch>> {
            if self.yielded {
                return Ok(None);
            }
            self.yielded = true;
            self.pos = self.next_pos.clone();
            Ok(Some(CollectedBatch {
                events: vec![(1, vec![7_u8; 3])],
                record_bytes: vec![128],
            }))
        }

        fn position(&self) -> Vec<u8> {
            self.pos.clone()
        }
    }

    fn write_send_error() -> SendError {
        SendError::WriteError(WriteError::Stopped(VarInt::from_u32(0)))
    }

    fn write_sender_error() -> SenderError {
        SenderError::Send(write_send_error())
    }

    fn serialization_failure(message: &str) -> SendError {
        SendError::SerializationFailure(Box::new(bincode::ErrorKind::Custom(message.to_string())))
    }

    /// Replays scripted `send_header` and `send_batch` results in order.
    /// Once a queue is exhausted, subsequent calls return `Ok(())`. Reconnect
    /// always returns `Reconnected`. Use a dedicated sender type when a test
    /// needs different behavior (e.g. triggering shutdown from within
    /// `reconnect`, or making `reconnect` itself fail).
    struct ScriptedSender {
        header_results: VecDeque<std::result::Result<(), SenderError>>,
        batch_results: VecDeque<std::result::Result<(), SendError>>,
        header_attempts: usize,
        batch_attempts: usize,
        reconnects: usize,
    }

    impl ScriptedSender {
        fn new() -> Self {
            Self {
                header_results: VecDeque::new(),
                batch_results: VecDeque::new(),
                header_attempts: 0,
                batch_attempts: 0,
                reconnects: 0,
            }
        }

        fn with_header_results<I>(mut self, results: I) -> Self
        where
            I: IntoIterator<Item = std::result::Result<(), SenderError>>,
        {
            self.header_results.extend(results);
            self
        }

        fn with_batch_results<I>(mut self, results: I) -> Self
        where
            I: IntoIterator<Item = std::result::Result<(), SendError>>,
        {
            self.batch_results.extend(results);
            self
        }
    }

    #[async_trait]
    impl PipelineSender for ScriptedSender {
        async fn send_header(
            &mut self,
            _protocol: RawEventKind,
        ) -> std::result::Result<(), SenderError> {
            self.header_attempts += 1;
            self.header_results.pop_front().unwrap_or(Ok(()))
        }

        async fn send_batch(
            &mut self,
            _events: &[(i64, Vec<u8>)],
        ) -> std::result::Result<(), SendError> {
            self.batch_attempts += 1;
            self.batch_results.pop_front().unwrap_or(Ok(()))
        }

        async fn reconnect(&mut self) -> std::result::Result<ReconnectOutcome, SenderError> {
            self.reconnects += 1;
            Ok(ReconnectOutcome::Reconnected)
        }
    }

    /// Triggers shutdown on its first reconnect, modeling the case where a
    /// signal arrives while the pipeline is recovering from a write error.
    /// The first batch attempt fails with a `WriteError`; subsequent attempts
    /// succeed, so the shutdown flush has work to do.
    struct ShutdownOnReconnectSender {
        send_attempts: usize,
        reconnects: usize,
        header_sends: usize,
        shutdown: watch::Sender<bool>,
    }

    #[async_trait]
    impl PipelineSender for ShutdownOnReconnectSender {
        async fn send_header(
            &mut self,
            _protocol: RawEventKind,
        ) -> std::result::Result<(), SenderError> {
            self.header_sends += 1;
            Ok(())
        }

        async fn send_batch(
            &mut self,
            _events: &[(i64, Vec<u8>)],
        ) -> std::result::Result<(), SendError> {
            self.send_attempts += 1;
            if self.send_attempts == 1 {
                return Err(write_send_error());
            }
            Ok(())
        }

        async fn reconnect(&mut self) -> std::result::Result<ReconnectOutcome, SenderError> {
            self.reconnects += 1;
            let _ = self.shutdown.send(true);
            Ok(ReconnectOutcome::Reconnected)
        }
    }

    #[tokio::test]
    async fn shutdown_after_write_error_flushes_pending_batch_and_advances_checkpoint() {
        let next_pos = b"12345".to_vec();
        let (shutdown_tx, shutdown) = watch::channel(false);
        let mut collector = OneBatchCollector {
            yielded: false,
            pos: Vec::new(),
            next_pos: next_pos.clone(),
        };
        let mut sender = ShutdownOnReconnectSender {
            send_attempts: 0,
            reconnects: 0,
            header_sends: 0,
            shutdown: shutdown_tx,
        };
        let mut seen_bytes = Vec::new();

        run_pipeline_with_sender(&mut sender, &mut collector, shutdown, &mut |bytes| {
            seen_bytes.push(bytes);
        })
        .await
        .expect("the scripted sender succeeds after one reconnect");

        assert_eq!(collector.position(), next_pos);
        assert_eq!(seen_bytes, vec![128]);
        assert_eq!(sender.send_attempts, 2);
        assert_eq!(sender.reconnects, 1);
    }

    #[tokio::test]
    async fn retries_same_batch_until_send_succeeds() {
        let (_shutdown_tx, shutdown) = watch::channel(false);
        let mut collector = OneBatchCollector {
            yielded: false,
            pos: Vec::new(),
            next_pos: b"777".to_vec(),
        };
        let mut sender = ScriptedSender::new()
            .with_batch_results([Err(write_send_error()), Err(write_send_error())]);
        let mut seen_bytes = Vec::new();

        run_pipeline_with_sender(&mut sender, &mut collector, shutdown, &mut |bytes| {
            seen_bytes.push(bytes);
        })
        .await
        .expect("the sender succeeds on the third attempt");

        assert_eq!(collector.position(), b"777".to_vec());
        assert_eq!(seen_bytes, vec![128]);
        assert_eq!(sender.batch_attempts, 3);
        assert_eq!(sender.reconnects, 2);
        // One pre-pipeline header send plus one per reconnect retry.
        assert_eq!(sender.header_attempts, 3);
    }

    /// Always fails the batch with a `WriteError`; the first reconnect
    /// triggers shutdown so the pipeline reaches the shutdown flush which
    /// then also fails. Used to confirm the second batch attempt happens
    /// before the error propagates out.
    struct AlwaysFailingShutdownOnReconnectSender {
        header_sends: usize,
        send_attempts: usize,
        shutdown: watch::Sender<bool>,
    }

    #[async_trait]
    impl PipelineSender for AlwaysFailingShutdownOnReconnectSender {
        async fn send_header(
            &mut self,
            _protocol: RawEventKind,
        ) -> std::result::Result<(), SenderError> {
            self.header_sends += 1;
            Ok(())
        }

        async fn send_batch(
            &mut self,
            _events: &[(i64, Vec<u8>)],
        ) -> std::result::Result<(), SendError> {
            self.send_attempts += 1;
            Err(write_send_error())
        }

        async fn reconnect(&mut self) -> std::result::Result<ReconnectOutcome, SenderError> {
            let _ = self.shutdown.send(true);
            Ok(ReconnectOutcome::Reconnected)
        }
    }

    #[tokio::test]
    async fn records_report_bytes_before_send_failure() {
        let (shutdown_tx, shutdown) = watch::channel(false);
        let mut collector = OneBatchCollector {
            yielded: false,
            pos: Vec::new(),
            next_pos: b"9".to_vec(),
        };
        let mut sender = AlwaysFailingShutdownOnReconnectSender {
            header_sends: 0,
            send_attempts: 0,
            shutdown: shutdown_tx,
        };
        let mut seen_bytes = Vec::new();

        let error = run_pipeline_with_sender(&mut sender, &mut collector, shutdown, &mut |bytes| {
            seen_bytes.push(bytes);
        })
        .await
        .expect_err("send failure should propagate");

        assert!(
            error.to_string().contains("WriteError"),
            "unexpected error: {error}"
        );
        assert_eq!(seen_bytes, vec![128]);
        assert_eq!(sender.send_attempts, 2);
    }

    struct ReconnectFailingSender {
        reconnects: usize,
    }

    #[async_trait]
    impl PipelineSender for ReconnectFailingSender {
        async fn send_header(
            &mut self,
            _protocol: RawEventKind,
        ) -> std::result::Result<(), SenderError> {
            Ok(())
        }

        async fn send_batch(
            &mut self,
            _events: &[(i64, Vec<u8>)],
        ) -> std::result::Result<(), SendError> {
            Err(write_send_error())
        }

        async fn reconnect(&mut self) -> std::result::Result<ReconnectOutcome, SenderError> {
            self.reconnects += 1;
            Err(SenderError::Context {
                context: "reconnect failed",
                source: anyhow::anyhow!("reconnect failed"),
            })
        }
    }

    #[tokio::test]
    async fn propagates_reconnect_failure() {
        let (_shutdown_tx, shutdown) = watch::channel(false);
        let mut collector = OneBatchCollector {
            yielded: false,
            pos: Vec::new(),
            next_pos: b"42".to_vec(),
        };
        let mut sender = ReconnectFailingSender { reconnects: 0 };

        let error = run_pipeline_with_sender(&mut sender, &mut collector, shutdown, &mut |_| {})
            .await
            .expect_err("reconnect failures must be returned to the caller");

        assert_eq!(sender.reconnects, 1);
        assert!(error.to_string().contains("reconnect failed"));
    }

    #[tokio::test]
    async fn propagates_non_write_send_error_without_reconnect() {
        let (_shutdown_tx, shutdown) = watch::channel(false);
        let mut collector = OneBatchCollector {
            yielded: false,
            pos: Vec::new(),
            next_pos: b"44".to_vec(),
        };
        let mut sender = ScriptedSender::new()
            .with_batch_results([Err(serialization_failure("non-write failure"))]);

        let error = run_pipeline_with_sender(&mut sender, &mut collector, shutdown, &mut |_| {})
            .await
            .expect_err("non-write send errors must be returned immediately");

        assert_eq!(sender.batch_attempts, 1);
        assert_eq!(sender.reconnects, 0);
        assert!(
            error.to_string().contains("SerializationFailure"),
            "unexpected error: {error}",
        );
    }

    struct ShutdownNonWriteErrorSender {
        send_attempts: usize,
        reconnects: usize,
        shutdown: watch::Sender<bool>,
    }

    #[async_trait]
    impl PipelineSender for ShutdownNonWriteErrorSender {
        async fn send_header(
            &mut self,
            _protocol: RawEventKind,
        ) -> std::result::Result<(), SenderError> {
            Ok(())
        }

        async fn send_batch(
            &mut self,
            _events: &[(i64, Vec<u8>)],
        ) -> std::result::Result<(), SendError> {
            self.send_attempts += 1;
            if self.send_attempts == 1 {
                return Err(write_send_error());
            }
            Err(serialization_failure("shutdown flush failed"))
        }

        async fn reconnect(&mut self) -> std::result::Result<ReconnectOutcome, SenderError> {
            self.reconnects += 1;
            let _ = self.shutdown.send(true);
            Ok(ReconnectOutcome::Reconnected)
        }
    }

    /// Models the real sender's header-first invariant: every fresh stream
    /// requires a `send_header` call before any `send_batch`, and `reconnect`
    /// produces a fresh stream so the header must be re-sent.
    struct HeaderStateSender {
        header_pending: bool,
        send_attempts: usize,
        reconnects: usize,
        header_sends: usize,
        header_violations: usize,
        shutdown: watch::Sender<bool>,
    }

    #[async_trait]
    impl PipelineSender for HeaderStateSender {
        async fn send_header(
            &mut self,
            _protocol: RawEventKind,
        ) -> std::result::Result<(), SenderError> {
            self.header_sends += 1;
            self.header_pending = false;
            Ok(())
        }

        async fn send_batch(
            &mut self,
            _events: &[(i64, Vec<u8>)],
        ) -> std::result::Result<(), SendError> {
            if self.header_pending {
                self.header_violations += 1;
            }
            self.send_attempts += 1;
            if self.send_attempts == 1 {
                return Err(write_send_error());
            }
            Ok(())
        }

        async fn reconnect(&mut self) -> std::result::Result<ReconnectOutcome, SenderError> {
            self.reconnects += 1;
            self.header_pending = true;
            let _ = self.shutdown.send(true);
            Ok(ReconnectOutcome::Reconnected)
        }
    }

    #[tokio::test]
    async fn shutdown_flush_sends_header_after_reconnect() {
        let (shutdown_tx, shutdown) = watch::channel(false);
        let mut collector = OneBatchCollector {
            yielded: false,
            pos: Vec::new(),
            next_pos: b"99".to_vec(),
        };
        let mut sender = HeaderStateSender {
            header_pending: true,
            send_attempts: 0,
            reconnects: 0,
            header_sends: 0,
            header_violations: 0,
            shutdown: shutdown_tx,
        };

        run_pipeline_with_sender(&mut sender, &mut collector, shutdown, &mut |_| {})
            .await
            .expect("the shutdown flush must succeed after reconnect");

        assert_eq!(sender.reconnects, 1);
        assert_eq!(sender.send_attempts, 2);
        // Header is sent once on the initial stream and once on the
        // post-reconnect stream used by the shutdown flush.
        assert_eq!(sender.header_sends, 2);
        assert_eq!(
            sender.header_violations, 0,
            "shutdown flush must not send a batch before the record header"
        );
    }

    struct ReloadDeferredSender {
        send_attempts: usize,
        reconnects: usize,
        header_sends: usize,
    }

    #[async_trait]
    impl PipelineSender for ReloadDeferredSender {
        async fn send_header(
            &mut self,
            _protocol: RawEventKind,
        ) -> std::result::Result<(), SenderError> {
            self.header_sends += 1;
            Ok(())
        }

        async fn send_batch(
            &mut self,
            _events: &[(i64, Vec<u8>)],
        ) -> std::result::Result<(), SendError> {
            self.send_attempts += 1;
            if self.send_attempts == 1 {
                return Err(write_send_error());
            }
            Ok(())
        }

        async fn reconnect(&mut self) -> std::result::Result<ReconnectOutcome, SenderError> {
            self.reconnects += 1;
            // Mirror the production fallback: rebuilt reload candidate
            // failed, but the last-known-good endpoint reconnected, so the
            // pipeline must keep running with reload intent still pending.
            Ok(ReconnectOutcome::ReloadDeferred(SenderError::Context {
                context: "reload candidate handshake failed",
                source: anyhow::anyhow!("reload candidate handshake failed"),
            }))
        }
    }

    #[tokio::test]
    async fn reload_deferred_reconnect_keeps_pipeline_running() {
        let next_pos = b"reload-deferred".to_vec();
        let (_shutdown_tx, shutdown) = watch::channel(false);
        let mut collector = OneBatchCollector {
            yielded: false,
            pos: Vec::new(),
            next_pos: next_pos.clone(),
        };
        let mut sender = ReloadDeferredSender {
            send_attempts: 0,
            reconnects: 0,
            header_sends: 0,
        };

        run_pipeline_with_sender(&mut sender, &mut collector, shutdown, &mut |_| {})
            .await
            .expect("ReloadDeferred must not be propagated as a pipeline error");

        assert_eq!(collector.position(), next_pos);
        assert_eq!(sender.reconnects, 1);
        assert_eq!(sender.send_attempts, 2);
        assert_eq!(sender.header_sends, 2);
    }

    #[tokio::test]
    async fn shutdown_flush_propagates_non_write_error() {
        let (shutdown_tx, shutdown) = watch::channel(false);
        let mut collector = OneBatchCollector {
            yielded: false,
            pos: Vec::new(),
            next_pos: b"55".to_vec(),
        };
        let mut sender = ShutdownNonWriteErrorSender {
            send_attempts: 0,
            reconnects: 0,
            shutdown: shutdown_tx,
        };

        let error = run_pipeline_with_sender(&mut sender, &mut collector, shutdown, &mut |_| {})
            .await
            .expect_err("shutdown flush failures must be returned");

        assert_eq!(sender.send_attempts, 2);
        assert_eq!(sender.reconnects, 1);
        assert!(
            error.to_string().contains("SerializationFailure"),
            "unexpected error: {error}",
        );
    }

    #[tokio::test]
    async fn pre_pipeline_header_write_error_triggers_reconnect_and_retries() {
        let (_shutdown_tx, shutdown) = watch::channel(false);
        let mut collector = OneBatchCollector {
            yielded: false,
            pos: Vec::new(),
            next_pos: b"21".to_vec(),
        };
        // Headers 1 and 2 fail; header 3 succeeds (default Ok).
        let mut sender = ScriptedSender::new()
            .with_header_results([Err(write_sender_error()), Err(write_sender_error())]);

        run_pipeline_with_sender(&mut sender, &mut collector, shutdown, &mut |_| {})
            .await
            .expect("header write errors should be retried after reconnect");

        assert_eq!(sender.header_attempts, 3);
        assert_eq!(sender.reconnects, 2);
        assert_eq!(sender.batch_attempts, 1);
    }

    #[tokio::test]
    async fn post_reconnect_header_write_error_triggers_another_reconnect() {
        let (_shutdown_tx, shutdown) = watch::channel(false);
        let mut collector = OneBatchCollector {
            yielded: false,
            pos: Vec::new(),
            next_pos: b"99".to_vec(),
        };
        // Pre-pipeline header (1) succeeds; the header sent after the batch
        // WriteError reconnect (2) fails; the next post-reconnect header (3)
        // succeeds (default Ok). Batch (1) fails with WriteError; batch (2)
        // succeeds (default Ok).
        let mut sender = ScriptedSender::new()
            .with_header_results([Ok(()), Err(write_sender_error())])
            .with_batch_results([Err(write_send_error())]);

        run_pipeline_with_sender(&mut sender, &mut collector, shutdown, &mut |_| {})
            .await
            .expect("header retries after reconnect should succeed eventually");

        // Pre-pipeline header (ok) + post-batch-WriteError header (fails) +
        // post-second-reconnect header (ok) = 3 header attempts; one
        // reconnect for the batch WriteError plus one for the header
        // WriteError = 2 reconnects.
        assert_eq!(sender.header_attempts, 3);
        assert_eq!(sender.reconnects, 2);
        assert_eq!(sender.batch_attempts, 2);
    }

    /// Always fails the header write with a `WriteError`; reconnect always
    /// succeeds but triggers shutdown on its first call. Without a shutdown
    /// check inside the header retry loop the pipeline would spin forever.
    struct ShutdownDuringHeaderRetrySender {
        header_attempts: usize,
        reconnects: usize,
        shutdown: watch::Sender<bool>,
    }

    #[async_trait]
    impl PipelineSender for ShutdownDuringHeaderRetrySender {
        async fn send_header(
            &mut self,
            _protocol: RawEventKind,
        ) -> std::result::Result<(), SenderError> {
            self.header_attempts += 1;
            Err(write_sender_error())
        }

        async fn send_batch(
            &mut self,
            _events: &[(i64, Vec<u8>)],
        ) -> std::result::Result<(), SendError> {
            unreachable!("send_batch must not be called when no header has been written");
        }

        async fn reconnect(&mut self) -> std::result::Result<ReconnectOutcome, SenderError> {
            self.reconnects += 1;
            let _ = self.shutdown.send(true);
            Ok(ReconnectOutcome::Reconnected)
        }
    }

    #[tokio::test]
    async fn header_retry_bails_out_when_shutdown_requested() {
        let (shutdown_tx, shutdown) = watch::channel(false);
        let mut collector = OneBatchCollector {
            yielded: false,
            pos: Vec::new(),
            next_pos: b"shutdown".to_vec(),
        };
        let mut sender = ShutdownDuringHeaderRetrySender {
            header_attempts: 0,
            reconnects: 0,
            shutdown: shutdown_tx,
        };

        run_pipeline_with_sender(&mut sender, &mut collector, shutdown, &mut |_| {})
            .await
            .expect("shutdown during header retry must stop the pipeline cleanly");

        // First header attempt fails -> reconnect (which trips shutdown) ->
        // header loop observes shutdown on its next iteration and bails.
        assert_eq!(sender.header_attempts, 1);
        assert_eq!(sender.reconnects, 1);
    }
}
