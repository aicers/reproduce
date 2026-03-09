use std::{
    fmt::Debug,
    fs::File,
    marker::PhantomData,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use anyhow::Result;
use async_trait::async_trait;
use csv::{Position, StringRecord, StringRecordsIntoIter};
use giganto_client::RawEventKind;
use serde::Serialize;
use tracing::{error, warn};

use crate::parser::sysmon_csv::TryFromSysmonRecord;
use crate::sender::{BATCH_SIZE, apply_timestamp_dedup};

use super::{CollectedBatch, Collector, POLLING_INTERVAL};

/// Collects Sysmon CSV records, parsing and batching them for sending.
///
/// After the source is exhausted, callers should check
/// [`SysmonCollector::needs_header_reset`] to determine whether the transport
/// header needs to be reset (matching the original `Producer::send_sysmon`
/// behaviour).
pub struct SysmonCollector<T> {
    iter: Option<StringRecordsIntoIter<File>>,
    protocol: RawEventKind,
    skip: u64,
    count_sent: u64,
    file_polling_mode: bool,
    dir_polling_mode: bool,
    running: Arc<AtomicBool>,
    pos: Position,
    last_record: StringRecord,
    reference_timestamp: Option<i64>,
    timestamp_offset: i64,
    success_cnt: u64,
    failed_cnt: u64,
    exhausted: bool,
    _marker: PhantomData<T>,
}

impl<T> SysmonCollector<T> {
    /// Creates a new `SysmonCollector` from a CSV record iterator.
    #[must_use]
    pub fn new(
        iter: StringRecordsIntoIter<File>,
        protocol: RawEventKind,
        skip: u64,
        count_sent: u64,
        file_polling_mode: bool,
        dir_polling_mode: bool,
        running: Arc<AtomicBool>,
    ) -> Self {
        Self {
            iter: Some(iter),
            protocol,
            skip,
            count_sent,
            file_polling_mode,
            dir_polling_mode,
            running,
            pos: Position::new(),
            last_record: StringRecord::new(),
            reference_timestamp: None,
            timestamp_offset: 0,
            success_cnt: 0,
            failed_cnt: 0,
            exhausted: false,
            _marker: PhantomData,
        }
    }

    /// Returns `true` if the source has been fully consumed.
    ///
    /// When this returns `true`, the caller should reset the transport header
    /// before switching to a different sysmon event type.
    #[must_use]
    pub fn needs_header_reset(&self) -> bool {
        self.exhausted
    }
}

#[async_trait]
impl<T> Collector for SysmonCollector<T>
where
    T: Serialize + TryFromSysmonRecord + Unpin + Debug + Send,
{
    fn protocol(&self) -> RawEventKind {
        self.protocol
    }

    #[allow(clippy::too_many_lines)]
    async fn next_batch(&mut self) -> Result<Option<CollectedBatch>> {
        if self.exhausted {
            return Ok(None);
        }

        let mut buf: Vec<(i64, Vec<u8>)> = Vec::new();
        let mut source_bytes = 0usize;

        while self.running.load(Ordering::SeqCst) {
            let Some(ref mut iter) = self.iter else {
                break;
            };
            let next_pos = iter.reader().position().clone();
            if let Some(result) = iter.next() {
                if next_pos.line() <= self.skip {
                    continue;
                }
                match result {
                    Ok(record) if record != self.last_record => {
                        self.last_record = record.clone();

                        let current_timestamp = if let Some(utc_time) = record.get(3) {
                            match crate::parser::sysmon_csv::parse_sysmon_time(utc_time) {
                                Ok(ts) => {
                                    if let Ok(nanos) = i64::try_from(ts.as_nanosecond()) {
                                        nanos
                                    } else {
                                        self.failed_cnt += 1;
                                        error!(
                                            "failed to convert timestamp to nanos #{}",
                                            next_pos.line()
                                        );
                                        continue;
                                    }
                                }
                                Err(e) => {
                                    self.failed_cnt += 1;
                                    error!("failed to parse sysmon time #{}: {e}", next_pos.line());
                                    continue;
                                }
                            }
                        } else {
                            self.failed_cnt += 1;
                            error!("missing time field #{}", next_pos.line());
                            continue;
                        };

                        let deduped_timestamp = apply_timestamp_dedup(
                            current_timestamp,
                            &mut self.reference_timestamp,
                            &mut self.timestamp_offset,
                        );

                        match T::try_from_sysmon_record(&record) {
                            Ok((event, _)) => {
                                let record_data = bincode::serialize(&event)?;
                                source_bytes += record.as_slice().len();
                                buf.push((deduped_timestamp, record_data));
                                self.success_cnt += 1;

                                if buf.len() >= BATCH_SIZE {
                                    self.pos = next_pos;
                                    return Ok(Some(CollectedBatch {
                                        events: buf,
                                        source_bytes,
                                    }));
                                }
                            }
                            Err(e) => {
                                self.failed_cnt += 1;
                                warn!("Failed to convert data #{}: {e}", next_pos.line());
                            }
                        }
                    }
                    Ok(_) => {
                        continue;
                    }
                    Err(e) => {
                        self.failed_cnt += 1;
                        warn!("Invalid record: {e}");
                    }
                }
                self.pos = next_pos;
                if self.count_sent != 0 && self.success_cnt >= self.count_sent {
                    self.exhausted = true;
                    break;
                }
            } else {
                if self.file_polling_mode && !self.dir_polling_mode {
                    tokio::time::sleep(POLLING_INTERVAL).await;
                    let mut taken = self.iter.take().expect("iter is Some inside this branch");
                    taken.reader_mut().seek(self.pos.clone())?;
                    self.iter = Some(taken.into_reader().into_records());
                    continue;
                }
                self.exhausted = true;
                break;
            }
        }

        if !self.running.load(Ordering::SeqCst) {
            self.exhausted = true;
        }

        if buf.is_empty() {
            return Ok(None);
        }

        Ok(Some(CollectedBatch {
            events: buf,
            source_bytes,
        }))
    }

    fn position(&self) -> u64 {
        self.pos.line()
    }

    fn stats(&self) -> (u64, u64) {
        (self.success_cnt, self.failed_cnt)
    }
}
