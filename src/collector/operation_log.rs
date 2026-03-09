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

use crate::parser::operation_log;
use crate::sender::BATCH_SIZE;

use super::{CollectedBatch, Collector, POLLING_INTERVAL};

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
        let mut source_bytes = 0usize;

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
                source_bytes += line.len();
                buf.push((timestamp, record_data));

                if buf.len() >= BATCH_SIZE {
                    return Ok(Some(CollectedBatch {
                        events: buf,
                        source_bytes,
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
            source_bytes,
        }))
    }

    fn position(&self) -> u64 {
        self.cnt
    }

    fn stats(&self) -> (u64, u64) {
        (self.success_cnt, self.failed_cnt)
    }
}
