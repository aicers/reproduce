use std::{
    fs::File,
    io::{BufRead, BufReader, Lines},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use anyhow::Result;
use async_trait::async_trait;
use giganto_client::RawEventKind;

use super::{CollectedBatch, Collector, POLLING_INTERVAL};
use crate::parser::operation_log;
use crate::sender::BATCH_SIZE;

/// Collects operation-log records from a line-oriented file, parsing and
/// batching them for sending.
pub struct OplogCollector {
    lines: Lines<BufReader<File>>,
    agent: String,
    skip: u64,
    count_sent: u64,
    file_polling_mode: bool,
    dir_polling_mode: bool,
    running: Arc<AtomicBool>,
    cnt: u64,
    success_cnt: u64,
    failed_cnt: u64,
    exhausted: bool,
}

impl OplogCollector {
    /// Creates a new `OplogCollector`.
    ///
    /// `agent` is the agent name embedded in each `OpLog` record.
    #[must_use]
    pub fn new(
        reader: BufReader<File>,
        agent: String,
        skip: u64,
        count_sent: u64,
        file_polling_mode: bool,
        dir_polling_mode: bool,
        running: Arc<AtomicBool>,
    ) -> Self {
        Self {
            lines: reader.lines(),
            agent,
            skip,
            count_sent,
            file_polling_mode,
            dir_polling_mode,
            running,
            cnt: 0,
            success_cnt: 0,
            failed_cnt: 0,
            exhausted: false,
        }
    }
}

#[async_trait]
impl Collector for OplogCollector {
    fn protocol(&self) -> RawEventKind {
        RawEventKind::OpLog
    }

    async fn next_batch(&mut self) -> Result<Option<CollectedBatch>> {
        if self.exhausted {
            return Ok(None);
        }

        let mut buf: Vec<(i64, Vec<u8>)> = Vec::new();
        let mut record_bytes: Vec<usize> = Vec::new();

        while self.running.load(Ordering::SeqCst) {
            if let Some(Ok(line)) = self.lines.next() {
                self.cnt += 1;
                if self.cnt <= self.skip {
                    continue;
                }

                let (oplog_data, timestamp) =
                    if let Ok(r) = operation_log::log_regex(&line, &self.agent) {
                        self.success_cnt += 1;
                        r
                    } else {
                        self.failed_cnt += 1;
                        continue;
                    };

                let record_data = bincode::serialize(&oplog_data)?;
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

    fn make_collector(content: &[u8], skip: u64) -> (OplogCollector, tempfile::TempDir) {
        make_collector_with_options(content, skip, 0, Arc::new(AtomicBool::new(true)))
    }

    fn make_collector_with_options(
        content: &[u8],
        skip: u64,
        count_sent: u64,
        running: Arc<AtomicBool>,
    ) -> (OplogCollector, tempfile::TempDir) {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("oplog.log");
        std::fs::write(&path, content).expect("write oplog");
        let file = std::fs::File::open(&path).expect("open oplog");
        let collector = OplogCollector::new(
            BufReader::new(file),
            "sensor".to_string(),
            skip,
            count_sent,
            false,
            false,
            running,
        );
        (collector, dir)
    }

    #[tokio::test]
    async fn oplog_collector_batches_valid_lines() {
        let content = b"2023-01-02T07:36:17Z INFO msg1\n2023-01-02T07:36:18Z WARN msg2\n";
        let (mut collector, _dir) = make_collector(content, 0);

        let mut total_events = 0;
        while let Some(batch) = collector.next_batch().await.expect("next_batch") {
            total_events += batch.events.len();
        }
        assert_eq!(total_events, 2);
        assert_eq!(collector.stats(), (2, 0));
    }

    #[tokio::test]
    async fn oplog_collector_counts_failures() {
        let content = b"2023-01-02T07:36:17Z INFO good\nnot-a-log-line\n";
        let (mut collector, _dir) = make_collector(content, 0);

        let mut total_events = 0;
        while let Some(batch) = collector.next_batch().await.expect("next_batch") {
            total_events += batch.events.len();
        }
        assert_eq!(total_events, 1);
        assert_eq!(collector.stats(), (1, 1));
    }

    #[tokio::test]
    async fn oplog_collector_returns_none_on_empty_input() {
        let (mut collector, _dir) = make_collector(b"", 0);
        let result = collector.next_batch().await.expect("next_batch");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn oplog_collector_skip_first_lines() {
        let content = b"2023-01-02T07:36:17Z INFO skip\n2023-01-02T07:36:18Z INFO keep\n";
        let (mut collector, _dir) = make_collector(content, 1);

        let mut total_events = 0;
        while let Some(batch) = collector.next_batch().await.expect("next_batch") {
            total_events += batch.events.len();
        }
        assert_eq!(total_events, 1);
    }

    #[tokio::test]
    async fn oplog_collector_respects_count_sent() {
        let running = Arc::new(AtomicBool::new(true));
        let content = b"2023-01-02T07:36:17Z INFO one\n2023-01-02T07:36:18Z INFO two\n";
        let (mut collector, _dir) = make_collector_with_options(content, 0, 1, running);

        let batch = collector
            .next_batch()
            .await
            .expect("next_batch should succeed")
            .expect("collector should emit one record before exhausting");

        assert_eq!(batch.events.len(), 1);
        assert_eq!(collector.position(), 1);
        assert_eq!(collector.stats(), (1, 0));
        assert_eq!(collector.protocol(), RawEventKind::OpLog);
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
    async fn oplog_collector_returns_none_when_running_flag_is_false() {
        let running = Arc::new(AtomicBool::new(false));
        let (mut collector, _dir) =
            make_collector_with_options(b"2023-01-02T07:36:17Z INFO line\n", 0, 0, running);

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
    async fn oplog_collector_flushes_at_batch_size_boundary() {
        let repeated = std::iter::repeat_n("2023-01-02T07:36:17Z INFO line", BATCH_SIZE + 1)
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
