use std::{
    fmt::Debug,
    fs::File,
    io::{BufRead, BufReader, Lines},
    marker::PhantomData,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use anyhow::Result;
use async_trait::async_trait;
use giganto_client::RawEventKind;
use serde::Serialize;

use super::{CollectedBatch, Collector, POLLING_INTERVAL};
use crate::parser::security_log::{ParseSecurityLog, SecurityLogInfo};
use crate::sender::BATCH_SIZE;

/// Collects security-log records from a line-oriented file, parsing and
/// batching them for sending.
pub struct SecurityLogCollector<T> {
    lines: Lines<BufReader<File>>,
    kind: String,
    skip: u64,
    count_sent: u64,
    file_polling_mode: bool,
    dir_polling_mode: bool,
    running: Arc<AtomicBool>,
    cnt: u64,
    time_serial: i64,
    success_cnt: u64,
    failed_cnt: u64,
    exhausted: bool,
    _marker: PhantomData<T>,
}

impl<T> SecurityLogCollector<T> {
    /// Creates a new `SecurityLogCollector`.
    ///
    /// `kind` is the Giganto kind string (e.g. `"wapples_waf_1"`) which is
    /// passed through to [`SecurityLogInfo::new`] for each record.
    #[must_use]
    pub fn new(
        reader: BufReader<File>,
        kind: String,
        skip: u64,
        count_sent: u64,
        file_polling_mode: bool,
        dir_polling_mode: bool,
        running: Arc<AtomicBool>,
    ) -> Self {
        Self {
            lines: reader.lines(),
            kind,
            skip,
            count_sent,
            file_polling_mode,
            dir_polling_mode,
            running,
            cnt: 0,
            time_serial: 0,
            success_cnt: 0,
            failed_cnt: 0,
            exhausted: false,
            _marker: PhantomData,
        }
    }
}

#[async_trait]
impl<T> Collector for SecurityLogCollector<T>
where
    T: Serialize + ParseSecurityLog + Unpin + Debug + Send,
{
    fn protocol(&self) -> RawEventKind {
        RawEventKind::SecuLog
    }

    async fn next_batch(&mut self) -> Result<Option<CollectedBatch>> {
        if self.exhausted {
            return Ok(None);
        }

        let kind_info = SecurityLogInfo::try_new(&self.kind)?;
        let mut buf: Vec<(i64, Vec<u8>)> = Vec::new();
        let mut record_bytes: Vec<usize> = Vec::new();

        while self.running.load(Ordering::SeqCst) {
            if let Some(Ok(line)) = self.lines.next() {
                self.cnt += 1;
                self.time_serial += 1;
                if self.time_serial > 999 {
                    self.time_serial = 1;
                }
                if self.cnt <= self.skip {
                    continue;
                }

                let (seculog_data, timestamp) = if let Ok(r) =
                    T::parse_security_log(&line, self.time_serial, kind_info.clone())
                {
                    self.success_cnt += 1;
                    r
                } else {
                    self.failed_cnt += 1;
                    continue;
                };

                let record_data = bincode::serialize(&seculog_data)?;
                record_bytes.push(line.len());
                buf.push((timestamp, record_data));

                if buf.len() >= BATCH_SIZE {
                    return Ok(Some(CollectedBatch {
                        events: buf,
                        record_bytes,
                    }));
                }

                if self.count_sent != 0 && self.success_cnt >= self.count_sent {
                    self.exhausted = true;
                    break;
                }
            } else {
                if self.file_polling_mode && !self.dir_polling_mode {
                    tokio::time::sleep(POLLING_INTERVAL).await;
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
        self.cnt
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
        io::BufReader,
        sync::{Arc, atomic::AtomicBool},
    };

    use tempfile::tempdir;

    use super::*;
    use crate::parser::security_log::Wapples;

    // Valid Wapples log lines that match the Wapples regex.
    const WAPPLES_LINE_1: &str = "<182>Jan 9 09:26:09 host wplogd: WAPPLES INTRUSION WAPPLES \
        DETECTION TIME : 2020-01-09 09:26:09 +0900 WAPPLES RULE NAME : \
        SQL Injection WAPPLES (client 192.168.1.100 WAPPLES) -> \
        (server 10.0.0.1:80)";
    const WAPPLES_LINE_2: &str = "<182>Jan 9 09:26:10 host wplogd: WAPPLES INTRUSION WAPPLES \
        DETECTION TIME : 2020-01-09 09:26:10 +0900 WAPPLES RULE NAME : \
        XSS WAPPLES (client 192.168.1.200 WAPPLES) -> \
        (server 10.0.0.2:443)";

    fn make_collector(
        content: &[u8],
        skip: u64,
    ) -> (SecurityLogCollector<Wapples>, tempfile::TempDir) {
        make_collector_with_options(content, skip, 0, Arc::new(AtomicBool::new(true)))
    }

    fn make_collector_with_options(
        content: &[u8],
        skip: u64,
        count_sent: u64,
        running: Arc<AtomicBool>,
    ) -> (SecurityLogCollector<Wapples>, tempfile::TempDir) {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("seculog.log");
        std::fs::write(&path, content).expect("write seculog");
        let file = std::fs::File::open(&path).expect("open seculog");
        let collector = SecurityLogCollector::<Wapples>::new(
            BufReader::new(file),
            "wapples_fw_6.0".to_string(),
            skip,
            count_sent,
            false,
            false,
            running,
        );
        (collector, dir)
    }

    #[tokio::test]
    async fn security_log_collector_batches_valid_wapples_records() {
        let content = format!("{WAPPLES_LINE_1}\n{WAPPLES_LINE_2}\n");
        let (mut collector, _dir) = make_collector(content.as_bytes(), 0);

        let mut total_events = 0;
        while let Some(batch) = collector.next_batch().await.expect("next_batch") {
            total_events += batch.events.len();
        }
        assert_eq!(total_events, 2);
        assert_eq!(collector.stats(), (2, 0));
    }

    #[tokio::test]
    async fn security_log_collector_counts_failures() {
        let content = format!("{WAPPLES_LINE_1}\nnot-a-log-line\n");
        let (mut collector, _dir) = make_collector(content.as_bytes(), 0);

        let mut total_events = 0;
        while let Some(batch) = collector.next_batch().await.expect("next_batch") {
            total_events += batch.events.len();
        }
        assert_eq!(total_events, 1);
        assert_eq!(collector.stats(), (1, 1));
    }

    #[tokio::test]
    async fn security_log_collector_returns_none_on_empty_input() {
        let (mut collector, _dir) = make_collector(b"", 0);
        let result = collector.next_batch().await.expect("next_batch");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn security_log_collector_skip_first_lines() {
        let content = format!("{WAPPLES_LINE_1}\n{WAPPLES_LINE_2}\n");
        let (mut collector, _dir) = make_collector(content.as_bytes(), 1);

        let mut total_events = 0;
        while let Some(batch) = collector.next_batch().await.expect("next_batch") {
            total_events += batch.events.len();
        }
        assert_eq!(total_events, 1);
    }

    #[tokio::test]
    async fn security_log_collector_respects_count_sent() {
        let running = Arc::new(AtomicBool::new(true));
        let content = format!("{WAPPLES_LINE_1}\n{WAPPLES_LINE_2}\n");
        let (mut collector, _dir) = make_collector_with_options(content.as_bytes(), 0, 1, running);

        let batch = collector
            .next_batch()
            .await
            .expect("next_batch should succeed")
            .expect("collector should emit one record before exhausting");

        assert_eq!(batch.events.len(), 1);
        assert_eq!(collector.position(), 1);
        assert_eq!(collector.stats(), (1, 0));
        assert_eq!(collector.protocol(), RawEventKind::SecuLog);
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
    async fn security_log_collector_returns_none_when_running_flag_is_false() {
        let running = Arc::new(AtomicBool::new(false));
        let (mut collector, _dir) =
            make_collector_with_options(WAPPLES_LINE_1.as_bytes(), 0, 0, running);

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
    async fn security_log_collector_wraps_time_serial_after_999_records() {
        let repeated = std::iter::repeat_n(WAPPLES_LINE_1, 1_000)
            .collect::<Vec<_>>()
            .join("\n");
        let content = format!("{repeated}\n");
        let (mut collector, _dir) = make_collector(content.as_bytes(), 0);

        while collector
            .next_batch()
            .await
            .expect("draining collector should succeed")
            .is_some()
        {}

        assert_eq!(collector.stats(), (1_000, 0));
        assert_eq!(collector.time_serial, 1);
    }

    #[tokio::test]
    async fn security_log_collector_flushes_at_batch_size_boundary() {
        let repeated = std::iter::repeat_n(WAPPLES_LINE_1, BATCH_SIZE + 1)
            .collect::<Vec<_>>()
            .join("\n");
        let content = format!("{repeated}\n");
        let (mut collector, _dir) = make_collector(content.as_bytes(), 0);

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
