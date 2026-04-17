pub mod file;
pub mod giganto_import;
pub mod log;
#[cfg(feature = "netflow")]
pub mod netflow;
pub mod operation_log;
pub mod security_log;
pub mod sysmon_csv;
pub mod zeek;

mod common;

use std::time::Duration;

use async_trait::async_trait;
pub(crate) use common::apply_timestamp_dedup;
use giganto_client::RawEventKind;
use thiserror::Error;
use tokio::sync::watch;

#[cfg(feature = "netflow")]
use crate::parser::netflow::NetflowError;

/// Defines how long polling collectors sleep after reaching EOF.
pub(crate) const POLLING_INTERVAL: Duration = Duration::from_secs(3);

/// Encodes a numeric collector position using the legacy decimal format.
pub(crate) fn position_bytes(position: u64) -> Vec<u8> {
    position.to_string().into_bytes()
}

/// Returns whether shutdown was requested on the receiver.
pub(crate) fn shutdown_requested(shutdown: &watch::Receiver<bool>) -> bool {
    *shutdown.borrow()
}

/// Waits for either the next polling interval or a shutdown signal.
pub(crate) async fn wait_for_poll_or_shutdown(shutdown: &mut watch::Receiver<bool>) -> bool {
    if shutdown_requested(shutdown) {
        return true;
    }

    tokio::select! {
        () = tokio::time::sleep(POLLING_INTERVAL) => shutdown_requested(shutdown),
        changed = shutdown.changed() => {
            changed.is_err() || shutdown_requested(shutdown)
        }
    }
}

/// Describes failures that can occur while collecting records from a source.
#[derive(Debug, Error)]
#[error(transparent)]
pub struct CollectorError(anyhow::Error);

impl From<anyhow::Error> for CollectorError {
    fn from(error: anyhow::Error) -> Self {
        Self(error)
    }
}

#[cfg(feature = "netflow")]
impl From<NetflowError> for CollectorError {
    fn from(error: NetflowError) -> Self {
        Self(anyhow::Error::new(error))
    }
}

/// Represents the result type used by collector implementations.
pub type CollectorResult<T> = std::result::Result<T, CollectorError>;

/// Stores a batch of parsed events ready for sending.
pub struct CollectedBatch {
    /// Stores the Giganto protocol kind for the serialized events in this batch.
    pub kind: RawEventKind,
    /// Stores parsed events as `(timestamp_nanos, serialized_record)` pairs.
    pub events: Vec<(i64, Vec<u8>)>,
    /// Stores per-record source byte sizes for per-record report accounting.
    pub record_bytes: Vec<usize>,
}

/// Produces batches of parsed events from a data source.
#[async_trait]
pub trait Collector: Send {
    /// Returns the next batch of events, or `None` when the source is
    /// exhausted (not polling or shutdown requested).
    ///
    /// # Errors
    ///
    /// Returns an error if reading or parsing the source data fails.
    async fn next_batch(&mut self) -> CollectorResult<Option<CollectedBatch>>;

    /// Returns the current position (line number or packet count) for
    /// checkpointing as raw bytes.
    fn position(&self) -> Vec<u8>;
}
