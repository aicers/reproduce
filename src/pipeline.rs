use anyhow::{Result, bail};
use giganto_client::frame::SendError;
use tracing::info;

use crate::collector::Collector;
use crate::sender::GigantoSender;

/// Drives a collector-to-sender pipeline until the collector is exhausted.
///
/// Each batch produced by the collector is sent to the Giganto server via
/// the sender. On a transient write error the connection is automatically
/// re-established and the failed batch is retried once.
///
/// `on_bytes` is called after each successful batch send with the number
/// of source bytes consumed, allowing the caller to update progress
/// reporting.
///
/// # Errors
///
/// Returns an error if the collector, sender, or reconnection logic fails.
pub async fn run_pipeline(
    collector: &mut dyn Collector,
    sender: &mut GigantoSender,
    mut on_bytes: impl FnMut(usize),
) -> Result<()> {
    let protocol = collector.protocol();

    while let Some(batch) = collector.next_batch().await? {
        sender.ensure_header_sent(protocol).await?;

        match sender.send_batch(&batch.events).await {
            Ok(()) => {}
            Err(SendError::WriteError(_)) => {
                sender.reconnect().await?;
                sender.ensure_header_sent(protocol).await?;
                sender
                    .send_batch(&batch.events)
                    .await
                    .map_err(|e| anyhow::anyhow!("failed to send batch after reconnect: {e:?}"))?;
            }
            Err(e) => bail!("{e:?}"),
        }

        on_bytes(batch.source_bytes);
    }

    let (success, failed) = collector.stats();
    info!(
        "Pipeline finished. Last position: {}, Success: {success}, Failed: {failed}",
        collector.position()
    );

    Ok(())
}
