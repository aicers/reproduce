use std::{fmt::Debug, fs::File, marker::PhantomData};

use async_trait::async_trait;
use csv::{Position, StringRecord, StringRecordsIntoIter};
use giganto_client::RawEventKind;
use serde::Serialize;
use tokio::sync::watch;
use tracing::{error, warn};

use super::{
    CollectedBatch, Collector, CollectorResult, apply_timestamp_dedup, position_bytes,
    shutdown_requested, wait_for_poll_or_shutdown,
};
use crate::parser::sysmon_csv::TryFromSysmonRecord;
use crate::sender::BATCH_SIZE;

/// Collects Sysmon CSV records, parsing and batching them for sending.
///
/// After the source is exhausted, callers should check
/// [`SysmonCollector::needs_header_reset`] to determine whether the transport
/// header needs to be reset (matching the original `Producer::send_sysmon`
/// behaviour).
#[allow(clippy::struct_excessive_bools)]
pub struct SysmonCollector<T> {
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
    reference_timestamp: Option<i64>,
    timestamp_offset: i64,
    has_consumed_rows: bool,
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
            reference_timestamp: None,
            timestamp_offset: 0,
            has_consumed_rows: false,
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

    /// Returns the number of successful and failed records observed so far.
    #[must_use]
    pub fn stats(&self) -> (u64, u64) {
        (self.success_cnt, self.failed_cnt)
    }
}

#[async_trait]
impl<T> Collector for SysmonCollector<T>
where
    T: Serialize + TryFromSysmonRecord + Unpin + Debug + Send,
{
    #[allow(clippy::too_many_lines)]
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
                                let record_data =
                                    bincode::serialize(&event).map_err(anyhow::Error::from)?;
                                record_bytes.push(record.as_slice().len());
                                buf.push((deduped_timestamp, record_data));
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

    use giganto_client::{RawEventKind, ingest::sysmon::ProcessCreate};
    use tempfile::tempdir;
    use tokio::sync::watch;

    use super::*;

    // Two distinct ProcessCreate records (different timestamp and process_id to avoid
    // the consecutive-duplicate guard).
    // Fields (tab-separated, 0-indexed): agent_name, agent_id, event_action, utc_time,
    // process_guid, process_id, image, file_version, description, product, company,
    // original_file_name, command_line, current_directory, user, logon_guid, logon_id,
    // terminal_session_id, integrity_level, hashes, parent_process_guid,
    // parent_process_id, parent_image, parent_command_line, parent_user
    const SYSMON_PC_1: &str = "sensor\tagent001\tProcess Create\t2023-01-15 14:30:45.123456\t{AAAA-0001}\t1234\tC:\\notepad.exe\t1.0\tdesc\tprod\tco\torig.exe\tnotepad.exe /f\tC:\\Windows\\\tSYSTEM\t{BBBB-0001}\t0x3e7\t0\tSystem\tSHA256=abc123\t{CCCC-0001}\t5678\tC:\\explorer.exe\texplorer.exe\tSYSTEM";
    const SYSMON_PC_2: &str = "sensor\tagent001\tProcess Create\t2023-01-15 14:30:46.000000\t{AAAA-0002}\t2345\tC:\\cmd.exe\t2.0\tdesc2\tprod2\tco2\torig2.exe\tcmd.exe /c\tC:\\Temp\\\tUSER\t{BBBB-0002}\t0x1234\t1\tMedium\tSHA256=def456\t{CCCC-0002}\t6789\tC:\\svchost.exe\tsvchost.exe\tSYSTEM";
    const SYSMON_PC_INVALID_TIME: &str = "sensor\tagent001\tProcess Create\tinvalid-time\t{AAAA-0003}\t3456\tC:\\calc.exe\t3.0\tdesc3\tprod3\tco3\torig3.exe\tcalc.exe\tC:\\Temp\\\tUSER\t{BBBB-0003}\t0x1235\t1\tMedium\tSHA256=ghi789\t{CCCC-0003}\t6790\tC:\\svchost.exe\tsvchost.exe\tSYSTEM";

    // open_sysmon_csv_file uses has_headers(true), so the CSV reader consumes
    // the first non-comment row as column headers.  Prepend a header row so
    // that every data row is yielded by into_records().
    const SYSMON_HEADER: &str = "agent_name\tagent_id\tevent_action\tutc_time\tprocess_guid\tprocess_id\timage\t\
         file_version\tdescription\tproduct\tcompany\toriginal_file_name\tcommand_line\t\
         current_directory\tuser\tlogon_guid\tlogon_id\tterminal_session_id\t\
         integrity_level\thashes\tparent_process_guid\tparent_process_id\t\
         parent_image\tparent_command_line\tparent_user";

    fn make_sysmon_collector(
        lines: &[&str],
        skip: u64,
    ) -> (SysmonCollector<ProcessCreate>, tempfile::TempDir) {
        let (_tx, shutdown) = watch::channel(false);
        make_sysmon_collector_with_options(lines, skip, 0, shutdown)
    }

    fn make_sysmon_collector_with_options(
        lines: &[&str],
        skip: u64,
        count_sent: u64,
        shutdown: watch::Receiver<bool>,
    ) -> (SysmonCollector<ProcessCreate>, tempfile::TempDir) {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("sysmon.csv");
        let mut f = std::fs::File::create(&path).expect("create sysmon.csv");
        writeln!(f, "{SYSMON_HEADER}").expect("write header");
        for line in lines {
            writeln!(f, "{line}").expect("write line");
        }
        drop(f);

        let reader =
            crate::parser::sysmon_csv::open_sysmon_csv_file(&path).expect("open sysmon csv");
        let iter = reader.into_records();
        let collector = SysmonCollector::<ProcessCreate>::new(
            iter,
            RawEventKind::ProcessCreate,
            skip,
            count_sent,
            false,
            false,
            shutdown,
        );
        (collector, dir)
    }

    #[tokio::test]
    async fn sysmon_collector_batches_valid_process_create_records() {
        let lines = [SYSMON_PC_1, SYSMON_PC_2];
        let (mut collector, _dir) = make_sysmon_collector(&lines, 0);

        let batch = collector
            .next_batch()
            .await
            .expect("next_batch")
            .expect("some batch");
        assert_eq!(batch.events.len(), 2);
        assert_eq!(batch.record_bytes.len(), 2);

        let none = collector.next_batch().await.expect("second call");
        assert!(none.is_none());
        // Position is 3 because the CSV header row counts as line 1, so the
        // two data rows end at line 3.
        assert_eq!(collector.position(), b"3".to_vec());
    }

    #[tokio::test]
    async fn sysmon_collector_stats_after_exhaustion() {
        let lines = [SYSMON_PC_1, SYSMON_PC_2];
        let (mut collector, _dir) = make_sysmon_collector(&lines, 0);

        while collector.next_batch().await.expect("next_batch").is_some() {}
        assert_eq!(collector.stats(), (2, 0));
    }

    #[tokio::test]
    async fn sysmon_collector_commits_checkpoint_after_all_parse_failures() {
        let invalid_2 = "sensor\tagent001\tProcess Create\tinvalid-time\t{AAAA-0004}\t4567\tC:\\calc.exe\t4.0\tdesc4\tprod4\tco4\torig4.exe\tcalc.exe\tC:\\Temp\\\tUSER\t{BBBB-0004}\t0x1236\t1\tMedium\tSHA256=jkl012\t{CCCC-0004}\t6791\tC:\\svchost.exe\tsvchost.exe\tSYSTEM";
        let invalid_3 = "sensor\tagent001\tProcess Create\tinvalid-time\t{AAAA-0005}\t5678\tC:\\calc.exe\t5.0\tdesc5\tprod5\tco5\torig5.exe\tcalc.exe\tC:\\Temp\\\tUSER\t{BBBB-0005}\t0x1237\t1\tMedium\tSHA256=mno345\t{CCCC-0005}\t6792\tC:\\svchost.exe\tsvchost.exe\tSYSTEM";
        let (_tx, shutdown) = watch::channel(false);
        let (mut collector, _dir) = make_sysmon_collector_with_options(
            &[SYSMON_PC_INVALID_TIME, invalid_2, invalid_3],
            0,
            0,
            shutdown,
        );

        assert!(
            collector
                .next_batch()
                .await
                .expect("invalid rows should not abort the collector")
                .is_none()
        );
        assert_eq!(collector.position(), b"4".to_vec());
        assert_eq!(collector.stats(), (0, 3));
        assert!(collector.needs_header_reset());
    }

    #[tokio::test]
    async fn sysmon_collector_caps_checkpoint_to_actual_rows_when_skip_is_too_large() {
        let lines = [SYSMON_PC_1, SYSMON_PC_2];
        let (mut collector, _dir) = make_sysmon_collector(&lines, 10);

        assert!(collector.next_batch().await.expect("next_batch").is_none());
        assert_eq!(collector.position(), b"3".to_vec());
        assert_eq!(collector.stats(), (0, 0));
        assert!(collector.needs_header_reset());
    }

    #[tokio::test]
    async fn sysmon_collector_commits_checkpoint_after_parse_failure_beyond_batch_size() {
        let mut lines = (0..BATCH_SIZE)
            .map(|index| {
                if index % 2 == 0 {
                    SYSMON_PC_1
                } else {
                    SYSMON_PC_2
                }
            })
            .collect::<Vec<_>>();
        lines.push(SYSMON_PC_INVALID_TIME);
        let expected_success = u64::try_from(BATCH_SIZE).expect("batch size fits in u64");
        let (mut collector, _dir) = make_sysmon_collector(&lines, 0);

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
            format!("{}", BATCH_SIZE + 2).into_bytes()
        );
        assert_eq!(collector.stats(), (expected_success, 1));
        assert!(collector.needs_header_reset());
    }

    #[tokio::test]
    async fn sysmon_collector_returns_none_on_empty_file() {
        let (mut collector, _dir) = make_sysmon_collector(&[], 0);
        let result = collector.next_batch().await.expect("next_batch");
        assert!(result.is_none());
        assert_eq!(collector.position(), b"0".to_vec());
        assert_eq!(collector.stats(), (0, 0));
    }

    #[tokio::test]
    async fn sysmon_collector_preserves_zero_checkpoint_for_completely_empty_file() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("empty.csv");
        std::fs::File::create(&path).expect("create empty file");

        let reader =
            crate::parser::sysmon_csv::open_sysmon_csv_file(&path).expect("open empty csv");
        let iter = reader.into_records();
        let (_tx, shutdown) = watch::channel(false);
        let mut collector = SysmonCollector::<ProcessCreate>::new(
            iter,
            RawEventKind::ProcessCreate,
            0,
            0,
            false,
            false,
            shutdown,
        );

        assert!(collector.next_batch().await.expect("next_batch").is_none());
        assert_eq!(collector.position(), b"0".to_vec());
        assert_eq!(collector.stats(), (0, 0));
    }

    #[tokio::test]
    async fn sysmon_collector_respects_count_sent_and_sets_header_reset() {
        let (_tx, shutdown) = watch::channel(false);
        let (mut collector, _dir) =
            make_sysmon_collector_with_options(&[SYSMON_PC_1, SYSMON_PC_2], 0, 1, shutdown);

        let batch = collector
            .next_batch()
            .await
            .expect("next_batch should succeed")
            .expect("collector should emit one record before exhausting");

        assert_eq!(batch.events.len(), 1);
        assert_eq!(batch.kind, RawEventKind::ProcessCreate);
        assert!(collector.needs_header_reset());
        assert!(
            collector
                .next_batch()
                .await
                .expect("collector should be exhausted")
                .is_none()
        );
        assert_eq!(collector.position(), b"1".to_vec());
        assert_eq!(collector.stats(), (1, 0));
    }

    #[tokio::test]
    async fn sysmon_collector_skips_duplicates_and_counts_invalid_rows() {
        let lines = [
            SYSMON_PC_1,
            SYSMON_PC_1,
            SYSMON_PC_INVALID_TIME,
            SYSMON_PC_2,
        ];
        let (mut collector, _dir) = make_sysmon_collector(&lines, 0);

        while collector
            .next_batch()
            .await
            .expect("draining collector should succeed")
            .is_some()
        {}

        assert_eq!(collector.stats(), (2, 1));
        assert!(collector.needs_header_reset());
    }

    #[tokio::test]
    async fn sysmon_collector_returns_none_when_running_flag_is_false() {
        let (_tx, shutdown) = watch::channel(true);
        let (mut collector, _dir) =
            make_sysmon_collector_with_options(&[SYSMON_PC_1], 0, 0, shutdown);

        assert!(
            collector
                .next_batch()
                .await
                .expect("stopped collector should not fail")
                .is_none()
        );
        assert!(collector.needs_header_reset());
        assert_eq!(collector.stats(), (0, 0));
    }

    #[tokio::test]
    async fn sysmon_collector_flushes_at_batch_size_boundary() {
        let lines = (0..=BATCH_SIZE)
            .map(|index| {
                if index % 2 == 0 {
                    SYSMON_PC_1
                } else {
                    SYSMON_PC_2
                }
            })
            .collect::<Vec<_>>();
        let (mut collector, _dir) = make_sysmon_collector(&lines, 0);

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
        assert!(collector.needs_header_reset());
    }
}
