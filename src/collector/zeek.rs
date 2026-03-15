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

use super::{CollectedBatch, Collector, POLLING_INTERVAL, apply_timestamp_dedup};
use crate::parser::zeek::TryFromZeekRecord;
use crate::sender::BATCH_SIZE;

/// Collects Zeek TSV log records, parsing and batching them for sending.
pub struct ZeekCollector<T> {
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

impl<T> ZeekCollector<T> {
    /// Creates a new `ZeekCollector` from a CSV record iterator.
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
}

#[async_trait]
impl<T> Collector for ZeekCollector<T>
where
    T: Serialize + TryFromZeekRecord + Unpin + Debug + Send,
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
        let mut record_bytes: Vec<usize> = Vec::new();

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

                        let current_timestamp = if let Some(timestamp) = record.get(0) {
                            match crate::parser::zeek::parse_zeek_timestamp(timestamp) {
                                Ok(ts) => {
                                    if let Ok(nanos) = i64::try_from(ts.as_nanosecond()) {
                                        nanos
                                    } else {
                                        self.failed_cnt += 1;
                                        error!("timestamp conversion failed #{}", next_pos.line());
                                        continue;
                                    }
                                }
                                Err(e) => {
                                    self.failed_cnt += 1;
                                    error!("timestamp parsing failed #{}: {e}", next_pos.line());
                                    continue;
                                }
                            }
                        } else {
                            self.failed_cnt += 1;
                            error!("missing timestamp field #{}", next_pos.line());
                            continue;
                        };

                        let deduped_timestamp = apply_timestamp_dedup(
                            current_timestamp,
                            &mut self.reference_timestamp,
                            &mut self.timestamp_offset,
                        );

                        match T::try_from_zeek_record(&record) {
                            Ok((event, _)) => {
                                let record_data = bincode::serialize(&event)?;
                                record_bytes.push(record.as_slice().len());
                                buf.push((deduped_timestamp, record_data));
                                self.success_cnt += 1;

                                if buf.len() >= BATCH_SIZE {
                                    self.pos = next_pos;
                                    return Ok(Some(CollectedBatch {
                                        events: buf,
                                        record_bytes,
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
                    // Re-seek and recreate the iterator to pick up appended
                    // data.
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
            record_bytes,
        }))
    }

    fn position(&self) -> u64 {
        self.pos.line()
    }

    fn stats(&self) -> (u64, u64) {
        (self.success_cnt, self.failed_cnt)
    }

    fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::Write,
        sync::{Arc, atomic::AtomicBool},
    };

    use giganto_client::{RawEventKind, ingest::network::Conn};
    use tempfile::tempdir;

    use super::*;

    // Distinct Zeek conn.log lines (different UIDs so no dedup skip).
    const ZEEK_CONN_1: &str = "1669773412.689790\tuid001aaa\t192.168.1.77\t57655\t209.197.168.151\t1024\ttcp\tirc-dcc-data\t2.256935\t124\t42208\tSF\t-\t-\t0\tShAdDaFf\t28\t1592\t43\t44452\t-";
    const ZEEK_CONN_2: &str = "1669773413.000000\tuid002bbb\t10.0.0.1\t12345\t8.8.8.8\t443\ttcp\t-\t0.123456\t0\t1500\tSF\t-\t-\t0\tS\t1\t52\t1\t1552\t-";
    const ZEEK_CONN_3: &str = "1669773414.000000\tuid003ccc\t172.16.0.5\t9000\t1.1.1.1\t53\tudp\tdns\t0.001\t30\t200\tSF\t-\t-\t0\tDd\t1\t58\t1\t228\t-";
    const ZEEK_CONN_INVALID_TIME: &str = "invalid\tuid004ddd\t172.16.0.6\t9001\t1.1.1.2\t54\tudp\tdns\t0.001\t30\t200\tSF\t-\t-\t0\tDd\t1\t58\t1\t228\t-";

    fn make_conn_collector(lines: &[&str], skip: u64) -> (ZeekCollector<Conn>, tempfile::TempDir) {
        make_conn_collector_with_options(lines, skip, 0, Arc::new(AtomicBool::new(true)))
    }

    fn make_conn_collector_with_options(
        lines: &[&str],
        skip: u64,
        count_sent: u64,
        running: Arc<AtomicBool>,
    ) -> (ZeekCollector<Conn>, tempfile::TempDir) {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("conn.log");
        let mut f = std::fs::File::create(&path).expect("create conn.log");
        for line in lines {
            writeln!(f, "{line}").expect("write line");
        }
        drop(f);

        let reader = csv::ReaderBuilder::new()
            .comment(Some(b'#'))
            .delimiter(b'\t')
            .has_headers(false)
            .flexible(true)
            .from_path(&path)
            .expect("open csv");
        let iter = reader.into_records();
        let collector = ZeekCollector::<Conn>::new(
            iter,
            RawEventKind::Conn,
            skip,
            count_sent,
            false,
            false,
            running,
        );
        (collector, dir)
    }

    #[tokio::test]
    async fn zeek_collector_batches_valid_conn_records() {
        let lines = [ZEEK_CONN_1, ZEEK_CONN_2, ZEEK_CONN_3];
        let (mut collector, _dir) = make_conn_collector(&lines, 0);

        let batch = collector
            .next_batch()
            .await
            .expect("next_batch")
            .expect("some batch");
        assert_eq!(batch.events.len(), 3);
        assert_eq!(batch.record_bytes.len(), 3);

        let none = collector.next_batch().await.expect("second call");
        assert!(none.is_none());
    }

    #[tokio::test]
    async fn zeek_collector_skip_records() {
        // skip=1: positions 0 and 1 are skipped (lines ≤ 1), so only 1 record is kept.
        let lines = [ZEEK_CONN_1, ZEEK_CONN_2, ZEEK_CONN_3];
        let (mut collector, _dir) = make_conn_collector(&lines, 1);

        let batch = collector
            .next_batch()
            .await
            .expect("next_batch")
            .expect("some batch");
        assert_eq!(batch.events.len(), 2);
    }

    #[tokio::test]
    async fn zeek_collector_stats_after_exhaustion() {
        let lines = [ZEEK_CONN_1, ZEEK_CONN_2];
        let (mut collector, _dir) = make_conn_collector(&lines, 0);

        while collector.next_batch().await.expect("next_batch").is_some() {}
        assert_eq!(collector.stats(), (2, 0));
    }

    #[tokio::test]
    async fn zeek_collector_returns_none_on_empty_file() {
        let (mut collector, _dir) = make_conn_collector(&[], 0);
        let result = collector.next_batch().await.expect("next_batch");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn zeek_collector_respects_count_sent() {
        let running = Arc::new(AtomicBool::new(true));
        let (mut collector, _dir) =
            make_conn_collector_with_options(&[ZEEK_CONN_1, ZEEK_CONN_2], 0, 1, running);

        let batch = collector
            .next_batch()
            .await
            .expect("next_batch should succeed")
            .expect("collector should emit one record before exhausting");

        assert_eq!(batch.events.len(), 1);
        assert_eq!(collector.position(), 1);
        assert_eq!(collector.stats(), (1, 0));
        assert_eq!(collector.protocol(), RawEventKind::Conn);
        assert!(collector.is_running());
        assert!(
            collector
                .next_batch()
                .await
                .expect("collector should be exhausted")
                .is_none()
        );
    }

    #[tokio::test]
    async fn zeek_collector_skips_duplicates_and_counts_invalid_rows() {
        let lines = [
            ZEEK_CONN_1,
            ZEEK_CONN_1,
            ZEEK_CONN_INVALID_TIME,
            ZEEK_CONN_2,
        ];
        let (mut collector, _dir) = make_conn_collector(&lines, 0);

        while collector
            .next_batch()
            .await
            .expect("draining collector should succeed")
            .is_some()
        {}

        assert_eq!(collector.stats(), (2, 1));
    }

    #[tokio::test]
    async fn zeek_collector_returns_none_when_running_flag_is_false() {
        let running = Arc::new(AtomicBool::new(false));
        let (mut collector, _dir) = make_conn_collector_with_options(&[ZEEK_CONN_1], 0, 0, running);

        assert!(!collector.is_running());
        assert!(
            collector
                .next_batch()
                .await
                .expect("stopped collector should not fail")
                .is_none()
        );
        assert_eq!(collector.stats(), (0, 0));
    }

    #[tokio::test]
    async fn zeek_collector_flushes_at_batch_size_boundary() {
        let lines = (0..=BATCH_SIZE)
            .map(|index| {
                if index % 2 == 0 {
                    ZEEK_CONN_1
                } else {
                    ZEEK_CONN_2
                }
            })
            .collect::<Vec<_>>();
        let (mut collector, _dir) = make_conn_collector(&lines, 0);

        let first = collector
            .next_batch()
            .await
            .expect("first batch should succeed")
            .expect("collector should flush the first full batch");
        let second = collector
            .next_batch()
            .await
            .expect("second batch should succeed")
            .expect("collector should keep the remainder for the next call");

        assert_eq!(first.events.len(), BATCH_SIZE);
        assert_eq!(second.events.len(), 1);
        assert!(
            collector
                .next_batch()
                .await
                .expect("collector should then exhaust")
                .is_none()
        );
    }
}
