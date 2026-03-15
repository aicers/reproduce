use anyhow::{Result, bail};
use async_trait::async_trait;
use giganto_client::{RawEventKind, frame::SendError};
use tracing::info;

use crate::collector::Collector;
use crate::sender::GigantoSender;

#[async_trait]
trait PipelineSender {
    async fn ensure_header_sent(&mut self, protocol: RawEventKind) -> Result<()>;
    async fn send_batch(&mut self, events: &[(i64, Vec<u8>)]) -> Result<(), SendError>;
    async fn reconnect(&mut self) -> Result<()>;
}

#[async_trait]
impl PipelineSender for GigantoSender {
    async fn ensure_header_sent(&mut self, protocol: RawEventKind) -> Result<()> {
        GigantoSender::ensure_header_sent(self, protocol).await
    }

    async fn send_batch(&mut self, events: &[(i64, Vec<u8>)]) -> Result<(), SendError> {
        GigantoSender::send_batch(self, events).await
    }

    async fn reconnect(&mut self) -> Result<()> {
        GigantoSender::reconnect(self).await
    }
}

/// Drives a collector-to-sender pipeline until the collector is exhausted.
///
/// Each batch produced by the collector is sent to the Giganto server via
/// the sender. On a transient write error the connection is automatically
/// re-established and the same batch is retried until the send succeeds,
/// preserving the original producer behavior where buffered records were
/// never discarded on write failures. The shutdown signal is checked
/// before each send attempt so that the pipeline remains responsive to
/// `Ctrl-C` even during repeated reconnections.
///
/// `on_record_bytes` is called once per record with that record's source
/// byte size, allowing the caller to update per-record report accounting.
///
/// Returns the position of the last successfully sent batch. Callers
/// should use this value — not `collector.position()` — for
/// checkpointing, because the collector may have advanced past a batch
/// that was never successfully transmitted (e.g. shutdown during a
/// `WriteError` retry).
///
/// `initial_checkpoint` is the resume offset loaded from the checkpoint
/// file. It is returned unchanged if no batch is successfully sent
/// (e.g. shutdown before the first send), preventing the checkpoint
/// from regressing to zero.
///
/// # Errors
///
/// Returns an error if the collector, sender, or reconnection logic fails.
pub async fn run_pipeline(
    collector: &mut dyn Collector,
    sender: &mut GigantoSender,
    initial_checkpoint: u64,
    mut on_record_bytes: impl FnMut(usize),
) -> Result<u64> {
    run_pipeline_with_sender(collector, sender, initial_checkpoint, &mut on_record_bytes).await
}

async fn run_pipeline_with_sender<S, F>(
    collector: &mut dyn Collector,
    sender: &mut S,
    initial_checkpoint: u64,
    on_record_bytes: &mut F,
) -> Result<u64>
where
    S: PipelineSender + ?Sized,
    F: FnMut(usize) + ?Sized,
{
    let protocol = collector.protocol();
    let mut last_sent_pos = initial_checkpoint;

    while let Some(batch) = collector.next_batch().await? {
        for &bytes in &batch.record_bytes {
            on_record_bytes(bytes);
        }

        sender.ensure_header_sent(protocol).await?;
        let mut shutdown_requested = false;

        loop {
            if !collector.is_running() {
                shutdown_requested = true;
                break;
            }
            match sender.send_batch(&batch.events).await {
                Ok(()) => break,
                Err(SendError::WriteError(_)) => {
                    sender.reconnect().await?;
                    sender.ensure_header_sent(protocol).await?;
                }
                Err(e) => bail!("{e:?}"),
            }
        }

        if shutdown_requested {
            match sender.send_batch(&batch.events).await {
                Ok(()) => {}
                Err(e) => bail!("{e:?}"),
            }
        }

        last_sent_pos = collector.position();
    }

    let (success, failed) = collector.stats();
    info!(
        "Pipeline finished. Last position: {last_sent_pos}, Success: {success}, Failed: {failed}",
    );

    Ok(last_sent_pos)
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    use anyhow::Result;
    use async_trait::async_trait;
    use quinn::{VarInt, WriteError};

    use super::*;
    use crate::collector::{CollectedBatch, Collector};

    struct OneBatchCollector {
        running: Arc<AtomicBool>,
        yielded: bool,
        pos: u64,
        next_pos: u64,
    }

    #[async_trait]
    impl Collector for OneBatchCollector {
        fn protocol(&self) -> RawEventKind {
            RawEventKind::Log
        }

        async fn next_batch(&mut self) -> Result<Option<CollectedBatch>> {
            if self.yielded {
                return Ok(None);
            }
            self.yielded = true;
            self.pos = self.next_pos;
            Ok(Some(CollectedBatch {
                events: vec![(1, vec![7_u8; 3])],
                record_bytes: vec![128],
            }))
        }

        fn position(&self) -> u64 {
            self.pos
        }

        fn stats(&self) -> (u64, u64) {
            (u64::from(self.yielded), 0)
        }

        fn is_running(&self) -> bool {
            self.running.load(Ordering::SeqCst)
        }
    }

    struct ScriptedSender {
        send_attempts: usize,
        reconnects: usize,
        header_sends: usize,
        running: Arc<AtomicBool>,
    }

    #[async_trait]
    impl PipelineSender for ScriptedSender {
        async fn ensure_header_sent(&mut self, _protocol: RawEventKind) -> Result<()> {
            self.header_sends += 1;
            Ok(())
        }

        async fn send_batch(&mut self, _events: &[(i64, Vec<u8>)]) -> Result<(), SendError> {
            self.send_attempts += 1;
            if self.send_attempts == 1 {
                return Err(SendError::WriteError(WriteError::Stopped(
                    VarInt::from_u32(0),
                )));
            }
            Ok(())
        }

        async fn reconnect(&mut self) -> Result<()> {
            self.reconnects += 1;
            self.running.store(false, Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn shutdown_after_write_error_flushes_pending_batch_and_advances_checkpoint() {
        let initial_checkpoint = 5_000_u64;
        let next_pos = 12_345_u64;
        let running = Arc::new(AtomicBool::new(true));
        let mut collector = OneBatchCollector {
            running: running.clone(),
            yielded: false,
            pos: 0,
            next_pos,
        };
        let mut sender = ScriptedSender {
            send_attempts: 0,
            reconnects: 0,
            header_sends: 0,
            running,
        };
        let mut seen_bytes = Vec::new();

        let result = run_pipeline_with_sender(
            &mut collector,
            &mut sender,
            initial_checkpoint,
            &mut |bytes| seen_bytes.push(bytes),
        )
        .await
        .expect("the scripted sender succeeds after one reconnect");

        assert_eq!(collector.position(), next_pos);
        assert_eq!(result, next_pos);
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
        async fn ensure_header_sent(&mut self, _protocol: RawEventKind) -> Result<()> {
            self.header_sends += 1;
            Ok(())
        }

        async fn send_batch(&mut self, _events: &[(i64, Vec<u8>)]) -> Result<(), SendError> {
            self.send_attempts += 1;
            if self.send_attempts < 3 {
                return Err(SendError::WriteError(WriteError::Stopped(
                    VarInt::from_u32(0),
                )));
            }
            Ok(())
        }

        async fn reconnect(&mut self) -> Result<()> {
            self.reconnects += 1;
            Ok(())
        }
    }

    #[tokio::test]
    async fn retries_same_batch_until_send_succeeds() {
        let running = Arc::new(AtomicBool::new(true));
        let mut collector = OneBatchCollector {
            running,
            yielded: false,
            pos: 0,
            next_pos: 777,
        };
        let mut sender = MultiRetrySender {
            send_attempts: 0,
            reconnects: 0,
            header_sends: 0,
        };
        let mut seen_bytes = Vec::new();

        let result = run_pipeline_with_sender(&mut collector, &mut sender, 0, &mut |bytes| {
            seen_bytes.push(bytes);
        })
        .await
        .expect("the sender succeeds on the third attempt");

        assert_eq!(result, 777);
        assert_eq!(seen_bytes, vec![128]);
        assert_eq!(sender.send_attempts, 3);
        assert_eq!(sender.reconnects, 2);
        assert_eq!(sender.header_sends, 3);
    }

    struct FailingSender {
        header_sends: usize,
        send_attempts: usize,
        running: Arc<AtomicBool>,
    }

    #[async_trait]
    impl PipelineSender for FailingSender {
        async fn ensure_header_sent(&mut self, _protocol: RawEventKind) -> Result<()> {
            self.header_sends += 1;
            Ok(())
        }

        async fn send_batch(&mut self, _events: &[(i64, Vec<u8>)]) -> Result<(), SendError> {
            self.send_attempts += 1;
            Err(SendError::WriteError(WriteError::Stopped(
                VarInt::from_u32(0),
            )))
        }

        async fn reconnect(&mut self) -> Result<()> {
            self.running.store(false, Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn records_report_bytes_before_send_failure() {
        let running = Arc::new(AtomicBool::new(true));
        let mut collector = OneBatchCollector {
            running: running.clone(),
            yielded: false,
            pos: 0,
            next_pos: 9,
        };
        let mut sender = FailingSender {
            header_sends: 0,
            send_attempts: 0,
            running,
        };
        let mut seen_bytes = Vec::new();

        let err = run_pipeline_with_sender(&mut collector, &mut sender, 0, &mut |bytes| {
            seen_bytes.push(bytes);
        })
        .await
        .expect_err("send failure should propagate");

        assert!(
            err.to_string().contains("WriteError"),
            "unexpected error: {err}"
        );
        assert_eq!(seen_bytes, vec![128]);
        assert_eq!(sender.send_attempts, 2);
    }
}
