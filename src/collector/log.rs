use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
};

use anyhow::{Context, anyhow};
use async_trait::async_trait;
use giganto_client::{RawEventKind, ingest::log::Log};
use jiff::Timestamp;
use tokio::sync::watch;

use super::{
    CollectedBatch, Collector, CollectorResult, position_bytes, shutdown_requested,
    wait_for_poll_or_shutdown,
};

/// Collects raw log lines from a binary file, wrapping each in a `Log` record
/// for sending.
///
/// Each line is sent individually (batch size 1) with the current wall-clock
/// timestamp, matching the original `Producer::send_log` / `send_single_log`
/// behaviour.
pub struct LogCollector {
    lines: BinaryLines<BufReader<File>>,
    kind: String,
    count_sent: u64,
    file_polling_mode: bool,
    dir_polling_mode: bool,
    shutdown: watch::Receiver<bool>,
    conv_cnt: u64,
    skip: u64,
    committed_cnt: u64,
    pending_commit: Option<u64>,
    exhausted: bool,
}

impl LogCollector {
    /// Creates a new `LogCollector`.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be opened.
    pub fn new(
        file_name: &Path,
        kind: String,
        skip: u64,
        count_sent: u64,
        file_polling_mode: bool,
        dir_polling_mode: bool,
        shutdown: watch::Receiver<bool>,
    ) -> CollectorResult<Self> {
        let log_file = File::open(file_name)
            .map_err(|e| anyhow!("failed to open {}: {e}", file_name.display()))?;
        let lines = BinaryLines::new(BufReader::new(log_file));

        Ok(Self {
            lines,
            kind,
            count_sent,
            file_polling_mode,
            dir_polling_mode,
            shutdown,
            conv_cnt: 0,
            skip,
            committed_cnt: skip,
            pending_commit: None,
            exhausted: false,
        })
    }

    /// Returns the number of successful and failed records observed so far.
    #[must_use]
    pub fn stats(&self) -> (u64, u64) {
        let sent = self.committed_cnt.saturating_sub(self.skip);
        (sent, 0)
    }
}

#[async_trait]
impl Collector for LogCollector {
    async fn next_batch(&mut self) -> CollectorResult<Option<CollectedBatch>> {
        if let Some(position) = self.pending_commit.take() {
            self.committed_cnt = position;
        }

        if self.exhausted {
            return Ok(None);
        }

        while !shutdown_requested(&self.shutdown) {
            let line = match self.lines.next() {
                Some(Ok(line)) => {
                    if line.is_empty() {
                        continue;
                    }
                    line
                }
                Some(Err(e)) => {
                    self.exhausted = true;
                    return Err(anyhow!("Failed to convert input data: {e}").into());
                }
                None => {
                    if self.file_polling_mode && !self.dir_polling_mode {
                        if wait_for_poll_or_shutdown(&mut self.shutdown).await {
                            self.exhausted = true;
                            self.committed_cnt = self.conv_cnt;
                            return Ok(None);
                        }
                        continue;
                    }
                    self.exhausted = true;
                    self.committed_cnt = self.conv_cnt;
                    return Ok(None);
                }
            };

            // Skip the first `skip` lines (already consumed by the iterator
            // in the original code via `.skip()`).
            if self.conv_cnt < self.skip {
                self.conv_cnt += 1;
                continue;
            }

            let send_log = Log {
                kind: self.kind.clone(),
                log: line.clone(),
            };

            let timestamp = i64::try_from(Timestamp::now().as_nanosecond())
                .context("timestamp nanoseconds overflow")?;
            let record_data = bincode::serialize(&send_log).map_err(anyhow::Error::from)?;
            let record_bytes = vec![line.len()];

            self.conv_cnt += 1;

            if self.count_sent != 0 && self.conv_cnt - self.skip >= self.count_sent {
                self.exhausted = true;
            }

            self.pending_commit = Some(self.conv_cnt);
            return Ok(Some(CollectedBatch {
                kind: RawEventKind::Log,
                events: vec![(timestamp, record_data)],
                record_bytes,
            }));
        }

        self.exhausted = true;
        self.committed_cnt = self.conv_cnt;
        Ok(None)
    }

    fn position(&self) -> Vec<u8> {
        position_bytes(self.committed_cnt)
    }
}

/// An iterator over binary lines separated by `\n`, stripping trailing
/// `\r\n` or `\n`.
pub struct BinaryLines<B> {
    buf: B,
}

impl<B> BinaryLines<B> {
    /// Creates a new `BinaryLines` iterator.
    fn new(buf: B) -> Self {
        Self { buf }
    }
}

impl<B: BufRead> Iterator for BinaryLines<B> {
    type Item = Result<Vec<u8>, std::io::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut buf = Vec::new();
        match self.buf.read_until(b'\n', &mut buf) {
            Ok(0) => None,
            Ok(_) => {
                if matches!(buf.last(), Some(b'\n')) {
                    buf.pop();
                    if matches!(buf.last(), Some(b'\r')) {
                        buf.pop();
                    }
                }
                Some(Ok(buf))
            }
            Err(e) => Some(Err(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, BufRead, BufReader, Read, Write};

    use tempfile::tempdir;
    use tokio::sync::watch;

    use super::*;
    fn collect_binary_lines(data: &[u8]) -> Vec<Vec<u8>> {
        BinaryLines::new(BufReader::new(data))
            .map(|r| r.expect("io error in BinaryLines"))
            .collect()
    }

    struct FailingBuf;

    impl Read for FailingBuf {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("forced read failure"))
        }
    }

    impl BufRead for FailingBuf {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            Err(io::Error::other("forced fill_buf failure"))
        }

        fn consume(&mut self, _amt: usize) {}
    }

    fn make_log_collector(
        content: &[u8],
        skip: u64,
        count_sent: u64,
        shutdown: watch::Receiver<bool>,
    ) -> (LogCollector, tempfile::TempDir) {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("test.log");
        std::fs::write(&path, content).expect("log fixture should be written");
        let collector = LogCollector::new(
            &path,
            "kind".to_string(),
            skip,
            count_sent,
            false,
            false,
            shutdown,
        )
        .expect("log collector should be created");
        (collector, dir)
    }

    #[test]
    fn binary_lines_strips_lf() {
        assert_eq!(collect_binary_lines(b"a\nb\n"), vec![b"a", b"b"]);
    }

    #[test]
    fn binary_lines_strips_crlf() {
        assert_eq!(collect_binary_lines(b"a\r\nb\r\n"), vec![b"a", b"b"]);
    }

    #[test]
    fn binary_lines_empty_input() {
        let result = collect_binary_lines(b"");
        assert!(result.is_empty());
    }

    #[test]
    fn binary_lines_no_trailing_newline() {
        assert_eq!(collect_binary_lines(b"hello"), vec![b"hello"]);
    }

    #[test]
    fn binary_lines_propagates_reader_errors() {
        let err = BinaryLines::new(FailingBuf)
            .next()
            .expect("failing reader should still yield an iterator item")
            .expect_err("failing reader must propagate the I/O error");
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert_eq!(err.to_string(), "forced fill_buf failure");
    }

    #[tokio::test]
    async fn log_collector_returns_one_batch_per_nonempty_line() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("test.log");
        let mut f = std::fs::File::create(&path).expect("create file");
        writeln!(f, "line1").expect("write line1");
        writeln!(f, "line2").expect("write line2");
        drop(f);

        let (_tx, shutdown) = watch::channel(false);
        let mut collector =
            LogCollector::new(&path, "kind".to_string(), 0, 0, false, false, shutdown)
                .expect("create collector");

        let b1 = collector
            .next_batch()
            .await
            .expect("next_batch 1")
            .expect("some batch 1");
        assert_eq!(b1.events.len(), 1);

        let b2 = collector
            .next_batch()
            .await
            .expect("next_batch 2")
            .expect("some batch 2");
        assert_eq!(b2.events.len(), 1);

        let none = collector.next_batch().await.expect("next_batch 3");
        assert!(none.is_none());
    }

    #[tokio::test]
    async fn log_collector_skips_empty_lines() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("test.log");
        let mut f = std::fs::File::create(&path).expect("create file");
        writeln!(f, "line1").expect("write line1");
        writeln!(f).expect("write empty line");
        writeln!(f, "line2").expect("write line2");
        drop(f);

        let (_tx, shutdown) = watch::channel(false);
        let mut collector =
            LogCollector::new(&path, "kind".to_string(), 0, 0, false, false, shutdown)
                .expect("create collector");

        let mut event_count = 0;
        while let Some(batch) = collector.next_batch().await.expect("next_batch") {
            event_count += batch.events.len();
        }
        assert_eq!(event_count, 2);
    }

    #[tokio::test]
    async fn log_collector_exhausts_cleanly() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("test.log");
        std::fs::write(&path, b"line\n").expect("write");

        let (_tx, shutdown) = watch::channel(false);
        let mut collector =
            LogCollector::new(&path, "kind".to_string(), 0, 0, false, false, shutdown)
                .expect("create collector");

        collector.next_batch().await.expect("first call");
        let none = collector.next_batch().await.expect("second call");
        assert!(none.is_none());
        let none2 = collector.next_batch().await.expect("third call");
        assert!(none2.is_none());
    }

    #[tokio::test]
    async fn log_collector_stats_after_exhaustion() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("test.log");
        std::fs::write(&path, b"line1\nline2\n").expect("write");

        let (_tx, shutdown) = watch::channel(false);
        let mut collector =
            LogCollector::new(&path, "kind".to_string(), 0, 0, false, false, shutdown)
                .expect("create collector");

        while collector.next_batch().await.expect("next_batch").is_some() {}
        assert_eq!(collector.stats(), (2, 0));
    }

    #[tokio::test]
    async fn log_collector_respects_skip_and_count_sent() {
        let (_tx, shutdown) = watch::channel(false);
        let (mut collector, _dir) = make_log_collector(b"skip\nkeep\nextra\n", 1, 1, shutdown);

        let batch = collector
            .next_batch()
            .await
            .expect("next_batch should succeed")
            .expect("collector should emit the first unskipped line");

        assert_eq!(batch.events.len(), 1);
        assert_eq!(batch.record_bytes, vec![4]);
        assert_eq!(batch.kind, RawEventKind::Log);
        assert!(
            collector
                .next_batch()
                .await
                .expect("collector should be exhausted")
                .is_none()
        );
        assert_eq!(collector.position(), b"2".to_vec());
        assert_eq!(collector.stats(), (1, 0));
    }

    #[tokio::test]
    async fn log_collector_caps_checkpoint_to_actual_lines_when_skip_is_too_large() {
        let (_tx, shutdown) = watch::channel(false);
        let (mut collector, _dir) = make_log_collector(b"one\ntwo\n", 10, 0, shutdown);

        assert!(collector.next_batch().await.expect("next_batch").is_none());
        assert_eq!(collector.position(), b"2".to_vec());
        assert_eq!(collector.stats(), (0, 0));
    }

    #[tokio::test]
    async fn log_collector_returns_none_when_running_flag_is_false() {
        let (_tx, shutdown) = watch::channel(true);
        let (mut collector, _dir) = make_log_collector(b"line\n", 0, 0, shutdown);

        assert!(
            collector
                .next_batch()
                .await
                .expect("stopped collector should not fail")
                .is_none()
        );
        assert!(
            collector
                .next_batch()
                .await
                .expect("exhausted collector should stay empty")
                .is_none()
        );
        assert_eq!(collector.stats(), (0, 0));
    }
}
