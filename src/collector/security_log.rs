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

use crate::parser::security_log::{ParseSecurityLog, SecurityLogInfo};
use crate::sender::BATCH_SIZE;

use super::{CollectedBatch, Collector, POLLING_INTERVAL};

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

        let mut buf: Vec<(i64, Vec<u8>)> = Vec::new();
        let mut source_bytes = 0usize;

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
                    T::parse_security_log(&line, self.time_serial, SecurityLogInfo::new(&self.kind))
                {
                    self.success_cnt += 1;
                    r
                } else {
                    self.failed_cnt += 1;
                    continue;
                };

                let record_data = bincode::serialize(&seculog_data)?;
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
