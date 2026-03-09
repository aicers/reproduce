use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use giganto_client::{RawEventKind, ingest::log::Log};
use jiff::Timestamp;

use super::{CollectedBatch, Collector, POLLING_INTERVAL};

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
    running: Arc<AtomicBool>,
    conv_cnt: u64,
    skip: u64,
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
        running: Arc<AtomicBool>,
    ) -> Result<Self> {
        let log_file = File::open(file_name)
            .map_err(|e| anyhow!("failed to open {}: {e}", file_name.display()))?;
        let lines = BinaryLines::new(BufReader::new(log_file));

        Ok(Self {
            lines,
            kind,
            count_sent,
            file_polling_mode,
            dir_polling_mode,
            running,
            conv_cnt: 0,
            skip,
            exhausted: false,
        })
    }
}

#[async_trait]
impl Collector for LogCollector {
    fn protocol(&self) -> RawEventKind {
        RawEventKind::Log
    }

    async fn next_batch(&mut self) -> Result<Option<CollectedBatch>> {
        if self.exhausted {
            return Ok(None);
        }

        while self.running.load(Ordering::SeqCst) {
            let line = match self.lines.next() {
                Some(Ok(line)) => {
                    if line.is_empty() {
                        continue;
                    }
                    line
                }
                Some(Err(e)) => {
                    self.exhausted = true;
                    return Err(anyhow!("Failed to convert input data: {e}"));
                }
                None => {
                    if self.file_polling_mode && !self.dir_polling_mode {
                        tokio::time::sleep(POLLING_INTERVAL).await;
                        continue;
                    }
                    self.exhausted = true;
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
            let record_data = bincode::serialize(&send_log)?;
            let record_bytes = vec![line.len()];

            self.conv_cnt += 1;

            if self.count_sent != 0 && self.conv_cnt - self.skip >= self.count_sent {
                self.exhausted = true;
            }

            return Ok(Some(CollectedBatch {
                events: vec![(timestamp, record_data)],
                record_bytes,
            }));
        }

        self.exhausted = true;
        Ok(None)
    }

    fn position(&self) -> u64 {
        self.conv_cnt
    }

    fn stats(&self) -> (u64, u64) {
        let sent = self.conv_cnt.saturating_sub(self.skip);
        (sent, 0)
    }

    fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
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
