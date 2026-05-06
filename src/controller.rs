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
    async fn ensure_header_sent(
        &mut self,
        protocol: RawEventKind,
    ) -> std::result::Result<(), SenderError>;
    async fn send_batch(&mut self, events: &[(i64, Vec<u8>)])
    -> std::result::Result<(), SendError>;
    async fn reconnect(&mut self) -> std::result::Result<ReconnectOutcome, SenderError>;
}

#[async_trait]
impl PipelineSender for GigantoSender {
    async fn ensure_header_sent(
        &mut self,
        protocol: RawEventKind,
    ) -> std::result::Result<(), SenderError> {
        GigantoSender::ensure_header_sent(self, protocol).await
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
            // Both the header and the batch must be reconnect-retryable,
            // because a broken stream is observed at the first write on
            // that stream — which is the header, not the batch. Propagating
            // a header-level `WriteError` instead of reconnecting skips the
            // reload path and defeats `SIGHUP`-driven TLS rotation.
            if let Err(error) = sender.ensure_header_sent(batch.kind).await {
                match error {
                    SenderError::Send(SendError::WriteError(_)) => {
                        log_reconnect_outcome(sender.reconnect().await?);
                        continue;
                    }
                    other => return Err(PipelineError::Sender(other)),
                }
            }
            match sender.send_batch(&batch.events).await {
                Ok(()) => break,
                Err(SendError::WriteError(_)) => {
                    log_reconnect_outcome(sender.reconnect().await?);
                }
                Err(error) => return Err(PipelineError::Send(error)),
            }
        }

        if shutdown_requested {
            // The reconnect path resets `init_msg = true`, so a fresh
            // post-reconnect stream still requires the record header before
            // any payload write. Send it here so the final flush obeys the
            // same header-first invariant as the normal send path.
            if let Err(error) = sender.ensure_header_sent(batch.kind).await {
                return Err(PipelineError::Sender(error));
            }
            match sender.send_batch(&batch.events).await {
                Ok(()) => {}
                Err(error) => return Err(PipelineError::Send(error)),
            }
        }
    }

    Ok(())
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
        async fn next_batch(&mut self) -> CollectorResult<Option<CollectedBatch>> {
            if self.yielded {
                return Ok(None);
            }
            self.yielded = true;
            self.pos = self.next_pos.clone();
            Ok(Some(CollectedBatch {
                kind: RawEventKind::Log,
                events: vec![(1, vec![7_u8; 3])],
                record_bytes: vec![128],
            }))
        }

        fn position(&self) -> Vec<u8> {
            self.pos.clone()
        }
    }

    struct ScriptedSender {
        send_attempts: usize,
        reconnects: usize,
        header_sends: usize,
        shutdown: watch::Sender<bool>,
    }

    #[async_trait]
    impl PipelineSender for ScriptedSender {
        async fn ensure_header_sent(
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
                return Err(SendError::WriteError(WriteError::Stopped(
                    VarInt::from_u32(0),
                )));
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
        let mut sender = ScriptedSender {
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

    struct MultiRetrySender {
        send_attempts: usize,
        reconnects: usize,
        header_sends: usize,
    }

    #[async_trait]
    impl PipelineSender for MultiRetrySender {
        async fn ensure_header_sent(
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
            if self.send_attempts < 3 {
                return Err(SendError::WriteError(WriteError::Stopped(
                    VarInt::from_u32(0),
                )));
            }
            Ok(())
        }

        async fn reconnect(&mut self) -> std::result::Result<ReconnectOutcome, SenderError> {
            self.reconnects += 1;
            Ok(ReconnectOutcome::Reconnected)
        }
    }

    #[tokio::test]
    async fn retries_same_batch_until_send_succeeds() {
        let (_shutdown_tx, shutdown) = watch::channel(false);
        let mut collector = OneBatchCollector {
            yielded: false,
            pos: Vec::new(),
            next_pos: b"777".to_vec(),
        };
        let mut sender = MultiRetrySender {
            send_attempts: 0,
            reconnects: 0,
            header_sends: 0,
        };
        let mut seen_bytes = Vec::new();

        run_pipeline_with_sender(&mut sender, &mut collector, shutdown, &mut |bytes| {
            seen_bytes.push(bytes);
        })
        .await
        .expect("the sender succeeds on the third attempt");

        assert_eq!(collector.position(), b"777".to_vec());
        assert_eq!(seen_bytes, vec![128]);
        assert_eq!(sender.send_attempts, 3);
        assert_eq!(sender.reconnects, 2);
        assert_eq!(sender.header_sends, 3);
    }

    struct FailingSender {
        header_sends: usize,
        send_attempts: usize,
        shutdown: watch::Sender<bool>,
    }

    #[async_trait]
    impl PipelineSender for FailingSender {
        async fn ensure_header_sent(
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
            Err(SendError::WriteError(WriteError::Stopped(
                VarInt::from_u32(0),
            )))
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
        let mut sender = FailingSender {
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
        async fn ensure_header_sent(
            &mut self,
            _protocol: RawEventKind,
        ) -> std::result::Result<(), SenderError> {
            Ok(())
        }

        async fn send_batch(
            &mut self,
            _events: &[(i64, Vec<u8>)],
        ) -> std::result::Result<(), SendError> {
            Err(SendError::WriteError(WriteError::Stopped(
                VarInt::from_u32(0),
            )))
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

    fn serialization_failure(message: &str) -> SendError {
        SendError::SerializationFailure(Box::new(bincode::ErrorKind::Custom(message.to_string())))
    }

    struct NonWriteErrorSender {
        send_attempts: usize,
        reconnects: usize,
    }

    #[async_trait]
    impl PipelineSender for NonWriteErrorSender {
        async fn ensure_header_sent(
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
            Err(serialization_failure("non-write failure"))
        }

        async fn reconnect(&mut self) -> std::result::Result<ReconnectOutcome, SenderError> {
            self.reconnects += 1;
            Ok(ReconnectOutcome::Reconnected)
        }
    }

    #[tokio::test]
    async fn propagates_non_write_send_error_without_reconnect() {
        let (_shutdown_tx, shutdown) = watch::channel(false);
        let mut collector = OneBatchCollector {
            yielded: false,
            pos: Vec::new(),
            next_pos: b"44".to_vec(),
        };
        let mut sender = NonWriteErrorSender {
            send_attempts: 0,
            reconnects: 0,
        };

        let error = run_pipeline_with_sender(&mut sender, &mut collector, shutdown, &mut |_| {})
            .await
            .expect_err("non-write send errors must be returned immediately");

        assert_eq!(sender.send_attempts, 1);
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
        async fn ensure_header_sent(
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
                return Err(SendError::WriteError(WriteError::Stopped(
                    VarInt::from_u32(0),
                )));
            }
            Err(serialization_failure("shutdown flush failed"))
        }

        async fn reconnect(&mut self) -> std::result::Result<ReconnectOutcome, SenderError> {
            self.reconnects += 1;
            let _ = self.shutdown.send(true);
            Ok(ReconnectOutcome::Reconnected)
        }
    }

    /// Models the real sender's header-first invariant: `send_batch` must be
    /// preceded by `ensure_header_sent` on a fresh post-reconnect stream, and
    /// `reconnect` resets `init_msg` so the header must be re-sent.
    struct HeaderStateSender {
        init_msg: bool,
        send_attempts: usize,
        reconnects: usize,
        header_sends: usize,
        header_violations: usize,
        shutdown: watch::Sender<bool>,
    }

    #[async_trait]
    impl PipelineSender for HeaderStateSender {
        async fn ensure_header_sent(
            &mut self,
            _protocol: RawEventKind,
        ) -> std::result::Result<(), SenderError> {
            if self.init_msg {
                self.header_sends += 1;
                self.init_msg = false;
            }
            Ok(())
        }

        async fn send_batch(
            &mut self,
            _events: &[(i64, Vec<u8>)],
        ) -> std::result::Result<(), SendError> {
            if self.init_msg {
                self.header_violations += 1;
            }
            self.send_attempts += 1;
            if self.send_attempts == 1 {
                return Err(SendError::WriteError(WriteError::Stopped(
                    VarInt::from_u32(0),
                )));
            }
            Ok(())
        }

        async fn reconnect(&mut self) -> std::result::Result<ReconnectOutcome, SenderError> {
            self.reconnects += 1;
            self.init_msg = true;
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
            init_msg: true,
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
        async fn ensure_header_sent(
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
                return Err(SendError::WriteError(WriteError::Stopped(
                    VarInt::from_u32(0),
                )));
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
}
