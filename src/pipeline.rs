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
        sender.ensure_header_sent(protocol).await?;

        loop {
            if !collector.is_running() {
                return Ok(last_sent_pos);
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

        last_sent_pos = collector.position();

        for &bytes in &batch.record_bytes {
            on_record_bytes(bytes);
        }
    }

    let (success, failed) = collector.stats();
    info!(
        "Pipeline finished. Last position: {last_sent_pos}, Success: {success}, Failed: {failed}",
    );

    Ok(last_sent_pos)
}
