use std::{fmt::Debug, fs::File, marker::PhantomData};

use async_trait::async_trait;
use csv::{Position, StringRecord, StringRecordsIntoIter};
use giganto_client::RawEventKind;
use serde::Serialize;
use tokio::sync::watch;
use tracing::warn;

use super::{
    CollectedBatch, Collector, CollectorResult, position_bytes, shutdown_requested,
    wait_for_poll_or_shutdown,
};
use crate::parser::giganto_import::TryFromGigantoRecord;
use crate::sender::BATCH_SIZE;

/// Collects Giganto-exported CSV records, parsing and batching them for
/// sending.
#[allow(clippy::struct_excessive_bools)]
pub struct GigantoImportCollector<T> {
    iter: Option<StringRecordsIntoIter<File>>,
    protocol: RawEventKind,
    skip: u64,
    count_sent: u64,
    file_polling_mode: bool,
    dir_polling_mode: bool,
    shutdown: watch::Receiver<bool>,
    pos: Position,
    committed_line: u64,
    pending_commit: Option<u64>,
    last_record: StringRecord,
    has_consumed_rows: bool,
    success_cnt: u64,
    failed_cnt: u64,
    exhausted: bool,
    _marker: PhantomData<T>,
}

impl<T> GigantoImportCollector<T> {
    /// Creates a new `GigantoImportCollector` from a CSV record iterator.
    #[must_use]
    pub fn new(
        iter: StringRecordsIntoIter<File>,
        protocol: RawEventKind,
        skip: u64,
        count_sent: u64,
        file_polling_mode: bool,
        dir_polling_mode: bool,
        shutdown: watch::Receiver<bool>,
    ) -> Self {
        Self {
            iter: Some(iter),
            protocol,
            skip,
            count_sent,
            file_polling_mode,
            dir_polling_mode,
            shutdown,
            pos: Position::new(),
            committed_line: skip,
            pending_commit: None,
            last_record: StringRecord::new(),
            has_consumed_rows: false,
            success_cnt: 0,
            failed_cnt: 0,
            exhausted: false,
            _marker: PhantomData,
        }
    }

    /// Returns the number of successful and failed records observed so far.
    #[must_use]
    pub fn stats(&self) -> (u64, u64) {
        (self.success_cnt, self.failed_cnt)
    }
}

#[async_trait]
impl<T> Collector for GigantoImportCollector<T>
where
    T: Serialize + TryFromGigantoRecord + Unpin + Debug + Send,
{
    async fn next_batch(&mut self) -> CollectorResult<Option<CollectedBatch>> {
        if let Some(position) = self.pending_commit.take() {
            self.committed_line = position;
        }

        if self.exhausted {
            return Ok(None);
        }

        let mut buf: Vec<(i64, Vec<u8>)> = Vec::new();
        let mut record_bytes: Vec<usize> = Vec::new();

        while !shutdown_requested(&self.shutdown) {
            let Some(ref mut iter) = self.iter else {
                break;
            };
            let next_pos = iter.reader().position().clone();
            if let Some(result) = iter.next() {
                self.pos = next_pos.clone();
                self.has_consumed_rows = true;
                if next_pos.line() <= self.skip {
                    continue;
                }
                match result {
                    Ok(record) if record != self.last_record => {
                        self.last_record = record.clone();
                        match T::try_from_giganto_record(&record) {
                            Ok((event, timestamp)) => {
                                let record_data =
                                    bincode::serialize(&event).map_err(anyhow::Error::from)?;
                                record_bytes.push(record.as_slice().len());
                                buf.push((timestamp, record_data));
                                self.success_cnt += 1;

                                if buf.len() >= BATCH_SIZE {
                                    self.pos = next_pos;
                                    self.pending_commit = Some(self.pos.line());
                                    return Ok(Some(CollectedBatch {
                                        kind: self.protocol,
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
                if self.count_sent != 0 && self.success_cnt >= self.count_sent {
                    self.exhausted = true;
                    break;
                }
            } else {
                if self.file_polling_mode && !self.dir_polling_mode {
                    if wait_for_poll_or_shutdown(&mut self.shutdown).await {
                        self.exhausted = true;
                        break;
                    }
                    let mut taken = self.iter.take().expect("iter is Some inside this branch");
                    taken
                        .reader_mut()
                        .seek(self.pos.clone())
                        .map_err(anyhow::Error::from)?;
                    self.iter = Some(taken.into_reader().into_records());
                    continue;
                }
                self.exhausted = true;
                break;
            }
        }

        if shutdown_requested(&self.shutdown) {
            self.exhausted = true;
        }

        if buf.is_empty() {
            if self.has_consumed_rows {
                self.committed_line = self.pos.line();
            }
            return Ok(None);
        }

        self.pending_commit = Some(self.pos.line());
        Ok(Some(CollectedBatch {
            kind: self.protocol,
            events: buf,
            record_bytes,
        }))
    }

    fn position(&self) -> Vec<u8> {
        position_bytes(self.committed_line)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use giganto_client::{RawEventKind, ingest::network::Conn};
    use tempfile::tempdir;
    use tokio::sync::watch;

    use super::*;

    // Two distinct Conn Giganto-exported records (tab-separated, 17 fields each).
    // Fields: timestamp, skipped, orig_addr, orig_port, resp_addr, resp_port,
    // proto, conn_state, start_time, duration, service, orig_bytes, resp_bytes,
    // orig_pkts, resp_pkts, orig_l2_bytes, resp_l2_bytes
    const MIGR_CONN_1: &str = "1669773412.655728000\tsrc1\t192.168.1.77\t57655\t209.197.168.151\t1024\t6\tSF\t1669773412.655728000\t2256935000\tirc-dcc-data\t124\t42208\t28\t43\t1592\t44452";
    const MIGR_CONN_2: &str = "1669773413.000000000\tsrc2\t10.0.0.1\t12345\t8.8.8.8\t443\t6\tSF\t1669773413.000000000\t123456000\t-\t0\t1500\t1\t1\t52\t1552";

    fn make_conn_collector(
        lines: &[&str],
        skip: u64,
    ) -> (GigantoImportCollector<Conn>, tempfile::TempDir) {
        let (_tx, shutdown) = watch::channel(false);
        make_conn_collector_with_options(lines, skip, 0, shutdown)
    }

    fn make_conn_collector_with_options(
        lines: &[&str],
        skip: u64,
        count_sent: u64,
        shutdown: watch::Receiver<bool>,
    ) -> (GigantoImportCollector<Conn>, tempfile::TempDir) {
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
        let collector = GigantoImportCollector::<Conn>::new(
            iter,
            RawEventKind::Conn,
            skip,
            count_sent,
            false,
            false,
            shutdown,
        );
        (collector, dir)
    }

    #[tokio::test]
    async fn giganto_import_collector_batches_valid_conn_records() {
        let lines = [MIGR_CONN_1, MIGR_CONN_2];
        let (mut collector, _dir) = make_conn_collector(&lines, 0);

        let batch = collector
            .next_batch()
            .await
            .expect("next_batch")
            .expect("some batch");
        assert_eq!(batch.events.len(), 2);
        assert_eq!(batch.record_bytes.len(), 2);

        let none = collector.next_batch().await.expect("second call");
        assert!(none.is_none());
    }

    #[tokio::test]
    async fn giganto_import_collector_stats_after_exhaustion() {
        let lines = [MIGR_CONN_1, MIGR_CONN_2];
        let (mut collector, _dir) = make_conn_collector(&lines, 0);

        while collector.next_batch().await.expect("next_batch").is_some() {}
        assert_eq!(collector.stats(), (2, 0));
    }

    #[tokio::test]
    async fn giganto_import_collector_commits_checkpoint_after_all_parse_failures() {
        let (mut collector, _dir) =
            make_conn_collector(&["invalid\trow", "bad\trow\t2", "bad\trow\t3"], 0);

        assert!(
            collector
                .next_batch()
                .await
                .expect("invalid rows should not abort the collector")
                .is_none()
        );
        assert_eq!(collector.position(), b"3".to_vec());
        assert_eq!(collector.stats(), (0, 3));
    }

    #[tokio::test]
    async fn giganto_import_collector_caps_checkpoint_to_actual_rows_when_skip_is_too_large() {
        let lines = [MIGR_CONN_1, MIGR_CONN_2];
        let (mut collector, _dir) = make_conn_collector(&lines, 10);

        assert!(collector.next_batch().await.expect("next_batch").is_none());
        assert_eq!(collector.position(), b"2".to_vec());
        assert_eq!(collector.stats(), (0, 0));
    }

    #[tokio::test]
    async fn giganto_import_collector_commits_checkpoint_after_parse_failure_beyond_batch_size() {
        let mut lines = (0..BATCH_SIZE)
            .map(|index| {
                if index % 2 == 0 {
                    MIGR_CONN_1
                } else {
                    MIGR_CONN_2
                }
            })
            .collect::<Vec<_>>();
        lines.push("invalid\trow");
        let expected_success = u64::try_from(BATCH_SIZE).expect("batch size fits in u64");
        let (mut collector, _dir) = make_conn_collector(&lines, 0);

        let batch = collector
            .next_batch()
            .await
            .expect("next_batch should succeed")
            .expect("collector should flush the first full batch");

        assert_eq!(batch.events.len(), BATCH_SIZE);
        assert!(
            collector
                .next_batch()
                .await
                .expect("invalid tail should not abort the collector")
                .is_none()
        );
        assert_eq!(
            collector.position(),
            format!("{}", BATCH_SIZE + 1).into_bytes()
        );
        assert_eq!(collector.stats(), (expected_success, 1));
    }

    #[tokio::test]
    async fn giganto_import_collector_returns_none_on_empty_input() {
        let (mut collector, _dir) = make_conn_collector(&[], 0);
        let result = collector.next_batch().await.expect("next_batch");
        assert!(result.is_none());
        assert_eq!(collector.position(), b"0".to_vec());
        assert_eq!(collector.stats(), (0, 0));
    }

    #[tokio::test]
    async fn giganto_import_collector_respects_count_sent() {
        let (_tx, shutdown) = watch::channel(false);
        let (mut collector, _dir) =
            make_conn_collector_with_options(&[MIGR_CONN_1, MIGR_CONN_2], 0, 1, shutdown);

        let batch = collector
            .next_batch()
            .await
            .expect("next_batch should succeed")
            .expect("collector should emit one event before hitting the count limit");

        assert_eq!(batch.events.len(), 1);
        assert_eq!(batch.kind, RawEventKind::Conn);
        assert!(
            collector
                .next_batch()
                .await
                .expect("collector should now be exhausted")
                .is_none()
        );
        assert_eq!(collector.position(), b"1".to_vec());
        assert_eq!(collector.stats(), (1, 0));
    }

    #[tokio::test]
    async fn giganto_import_collector_skips_duplicates_and_counts_invalid_rows() {
        let lines = [MIGR_CONN_1, MIGR_CONN_1, "invalid\trow"];
        let (mut collector, _dir) = make_conn_collector(&lines, 0);

        let batch = collector
            .next_batch()
            .await
            .expect("next_batch should succeed")
            .expect("collector should keep the first valid record");

        assert_eq!(batch.events.len(), 1);

        while collector
            .next_batch()
            .await
            .expect("draining collector should succeed")
            .is_some()
        {}
        assert_eq!(collector.stats(), (1, 1));
    }

    #[tokio::test]
    async fn giganto_import_collector_returns_none_when_running_flag_is_false() {
        let (_tx, shutdown) = watch::channel(true);
        let (mut collector, _dir) =
            make_conn_collector_with_options(&[MIGR_CONN_1], 0, 0, shutdown);

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
    async fn giganto_import_collector_flushes_at_batch_size_boundary() {
        let lines = (0..=BATCH_SIZE)
            .map(|index| {
                if index % 2 == 0 {
                    MIGR_CONN_1
                } else {
                    MIGR_CONN_2
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
