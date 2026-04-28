use async_trait::async_trait;
use giganto_client::{RawEventKind, frame::SendError};
use thiserror::Error;
use tokio::sync::watch;

use crate::collector::{Collector, CollectorError};
use crate::sender::{GigantoSender, SenderError};

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
    async fn reconnect(&mut self) -> std::result::Result<(), SenderError>;
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

    async fn reconnect(&mut self) -> std::result::Result<(), SenderError> {
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
    // Send the stream header up front so the receiver can recognize the raw
    // event kind even when the collector has nothing to send. Without this,
    // an empty input would make the sender emit only the channel-close
    // marker, which the data store rejects with `unknown raw event kind`.
    sender.ensure_header_sent(collector.kind()).await?;

    while let Some(batch) = collector.next_batch().await? {
        for &bytes in &batch.record_bytes {
            on_record_bytes(bytes);
        }

        sender.ensure_header_sent(batch.kind).await?;
        let mut shutdown_requested = false;

        loop {
            if *shutdown.borrow() {
                shutdown_requested = true;
                break;
            }
            match sender.send_batch(&batch.events).await {
                Ok(()) => break,
                Err(SendError::WriteError(_)) => {
                    sender.reconnect().await?;
                    sender.ensure_header_sent(batch.kind).await?;
                }
                Err(error) => return Err(PipelineError::Send(error)),
            }
        }

        if shutdown_requested {
            match sender.send_batch(&batch.events).await {
                Ok(()) => {}
                Err(error) => return Err(PipelineError::Send(error)),
            }
        }
    }

    Ok(())
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

        async fn reconnect(&mut self) -> std::result::Result<(), SenderError> {
            self.reconnects += 1;
            let _ = self.shutdown.send(true);
            Ok(())
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

        async fn reconnect(&mut self) -> std::result::Result<(), SenderError> {
            self.reconnects += 1;
            Ok(())
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
        // One pre-pipeline header send, one per batch attempt, and one per
        // reconnect retry.
        assert_eq!(sender.header_sends, 4);
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

        async fn reconnect(&mut self) -> std::result::Result<(), SenderError> {
            let _ = self.shutdown.send(true);
            Ok(())
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

        async fn reconnect(&mut self) -> std::result::Result<(), SenderError> {
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

        async fn reconnect(&mut self) -> std::result::Result<(), SenderError> {
            self.reconnects += 1;
            Ok(())
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

        async fn reconnect(&mut self) -> std::result::Result<(), SenderError> {
            self.reconnects += 1;
            let _ = self.shutdown.send(true);
            Ok(())
        }
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
