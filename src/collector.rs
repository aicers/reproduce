pub mod log;
pub mod migration;
pub mod netflow;
pub mod operation_log;
pub mod security_log;
pub mod sysmon_csv;
pub mod zeek;

mod common;

use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
pub(crate) use common::apply_timestamp_dedup;
use giganto_client::RawEventKind;

/// Defines how long polling collectors sleep after reaching EOF.
pub(crate) const POLLING_INTERVAL: Duration = Duration::from_millis(3_000);

/// Stores a batch of parsed events ready for sending.
pub struct CollectedBatch {
    /// Parsed events as `(timestamp_nanos, serialized_record)` pairs.
    pub events: Vec<(i64, Vec<u8>)>,
    /// Per-record source byte sizes (for per-record report accounting).
    pub record_bytes: Vec<usize>,
}

/// Produces batches of parsed events from a data source.
#[async_trait]
pub trait Collector: Send {
    /// Returns the protocol kind for this collector.
    fn protocol(&self) -> RawEventKind;

    /// Returns the next batch of events, or `None` when the source is
    /// exhausted (not polling or shutdown requested).
    ///
    /// # Errors
    ///
    /// Returns an error if reading or parsing the source data fails.
    async fn next_batch(&mut self) -> Result<Option<CollectedBatch>>;

    /// Returns the current position (line number or packet count) for
    /// checkpointing.
    fn position(&self) -> u64;

    /// Returns `(success_count, failed_count)` for logging.
    fn stats(&self) -> (u64, u64);

    /// Returns `true` while the collector should keep running.
    ///
    /// When shutdown is requested (e.g. `Ctrl-C`), this returns `false`
    /// so that the pipeline can exit gracefully.
    fn is_running(&self) -> bool;
}
