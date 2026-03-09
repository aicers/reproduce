use std::{
    env,
    fmt::Debug,
    marker::PhantomData,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use anyhow::{Result, bail};
use async_trait::async_trait;
use giganto_client::RawEventKind;
use serde::Serialize;
use tracing::error;

use super::{CollectedBatch, Collector};
use crate::parser::netflow::{
    NetflowHeader, ParseNetflowDatasets, PktBuf, ProcessStats, Stats, TemplatesBox,
};
use crate::sender::BATCH_SIZE;

/// Collects Netflow records from a pcap file, parsing and batching them for
/// sending.
pub struct NetflowCollector<T> {
    handle: pcap::Capture<pcap::Offline>,
    protocol: RawEventKind,
    skip: u64,
    count_sent: u64,
    running: Arc<AtomicBool>,
    templates: TemplatesBox,
    tmpl_path: Option<String>,
    stats: Stats,
    pkt_cnt: u64,
    timestamp_old: u32,
    nanos: u32,
    exhausted: bool,
    _marker: PhantomData<T>,
}

impl<T> NetflowCollector<T> {
    /// Creates a new `NetflowCollector` from a pcap file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be opened or has an unsupported
    /// data-link type.
    pub fn new(
        filename: &Path,
        protocol: RawEventKind,
        skip: u64,
        count_sent: u64,
        running: Arc<AtomicBool>,
    ) -> Result<Self> {
        let tmpl_path = env::var("NETFLOW_TEMPLATES_PATH").ok();
        let templates = if let Some(ref path) = tmpl_path {
            TemplatesBox::from_path(path).unwrap_or_default()
        } else {
            TemplatesBox::new()
        };

        let handle = pcap::Capture::from_file(filename)?;
        if handle.get_datalink() != pcap::Linktype::ETHERNET {
            bail!(
                "Error: unknown datalink {:?} in {}",
                handle.get_datalink().get_name(),
                filename.display()
            );
        }

        Ok(Self {
            handle,
            protocol,
            skip,
            count_sent,
            running,
            templates,
            tmpl_path,
            stats: Stats::new(),
            pkt_cnt: 0,
            timestamp_old: 0,
            nanos: 1,
            exhausted: false,
            _marker: PhantomData,
        })
    }

    /// Returns a reference to the accumulated netflow processing statistics.
    #[must_use]
    pub fn netflow_stats(&self) -> &Stats {
        &self.stats
    }

    /// Persists netflow templates to disk if a template path was configured.
    ///
    /// This should be called after the collector is exhausted to avoid
    /// losing template state.
    pub fn save_templates(&self) {
        if !self.templates.is_empty()
            && let Some(ref path) = self.tmpl_path
            && let Err(e) = self.templates.save(path)
        {
            error!("{}. {}", e, path);
        }
    }
}

#[async_trait]
impl<T> Collector for NetflowCollector<T>
where
    T: Serialize + ParseNetflowDatasets + Unpin + Debug + Send,
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

        while let Ok(pkt) = self.handle.next_packet() {
            self.pkt_cnt += 1;
            if self.skip >= self.pkt_cnt {
                continue;
            }

            let mut input = PktBuf::new(&pkt);
            let rst = input.is_netflow();
            self.stats.add(rst, 1);
            if rst != ProcessStats::YesNetflowPackets {
                continue;
            }

            let Ok(header) = input.parse_netflow_header() else {
                self.stats.add(ProcessStats::InvalidNetflowPackets, 1);
                continue;
            };

            let (unix_secs, unix_nanos) = header.timestamp();
            if self.timestamp_old != unix_secs {
                self.nanos = unix_nanos;
            }
            self.timestamp_old = unix_secs;

            match header {
                NetflowHeader::V5(_) => {
                    self.stats.add(ProcessStats::NetflowV5DataPackets, 1);
                }
                NetflowHeader::V9(_) => {
                    self.stats.add(ProcessStats::NetflowV9DataPackets, 1);
                }
            }

            let events = T::parse_netflow_datasets(
                self.pkt_cnt,
                &mut self.templates,
                &header,
                &mut self.nanos,
                &mut input,
                &mut self.stats,
            )?;

            for (timestamp, event) in events {
                let record_data = bincode::serialize(&event)?;
                record_bytes.push(pkt.len());
                buf.push((timestamp, record_data));

                if buf.len() >= BATCH_SIZE {
                    return Ok(Some(CollectedBatch {
                        events: buf,
                        record_bytes,
                    }));
                }
            }

            // Netflow flushes per-packet: if any events were collected from
            // this packet, return the batch now.
            if !buf.is_empty() {
                return Ok(Some(CollectedBatch {
                    events: buf,
                    record_bytes,
                }));
            }

            if self.count_sent != 0 && self.pkt_cnt >= self.count_sent {
                self.exhausted = true;
                break;
            }

            if !self.running.load(Ordering::SeqCst) {
                self.exhausted = true;
                break;
            }
        }

        self.stats.add(
            ProcessStats::Packets,
            self.pkt_cnt.try_into().unwrap_or_default(),
        );

        self.exhausted = true;
        self.save_templates();

        if buf.is_empty() {
            return Ok(None);
        }

        Ok(Some(CollectedBatch {
            events: buf,
            record_bytes,
        }))
    }

    fn position(&self) -> u64 {
        self.pkt_cnt
    }

    fn stats(&self) -> (u64, u64) {
        // Netflow does not track individual success/failed the same way as
        // CSV-based collectors. Report packet count as success.
        (self.pkt_cnt, 0)
    }

    fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
}
