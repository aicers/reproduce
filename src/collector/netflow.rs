use std::{
    collections::VecDeque,
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
    pending_events: VecDeque<(i64, Vec<u8>, usize)>,
    exhausted: bool,
    finalized: bool,
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
            pending_events: VecDeque::new(),
            exhausted: false,
            finalized: false,
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

    fn drain_pending_batch(&mut self) -> Option<CollectedBatch> {
        if self.pending_events.is_empty() {
            return None;
        }

        let mut events = Vec::new();
        let mut record_bytes = Vec::new();
        while events.len() < BATCH_SIZE {
            let Some((timestamp, record_data, source_bytes)) = self.pending_events.pop_front()
            else {
                break;
            };
            events.push((timestamp, record_data));
            record_bytes.push(source_bytes);
        }

        Some(CollectedBatch {
            events,
            record_bytes,
        })
    }

    fn finalize(&mut self) {
        if self.finalized {
            return;
        }

        self.stats.add(
            ProcessStats::Packets,
            self.pkt_cnt.try_into().unwrap_or_default(),
        );
        self.save_templates();
        self.finalized = true;
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
        if let Some(batch) = self.drain_pending_batch() {
            return Ok(Some(batch));
        }

        if self.exhausted {
            self.finalize();
            return Ok(None);
        }

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

            let mut saw_events = false;
            for (timestamp, event) in events {
                let record_data = bincode::serialize(&event)?;
                self.pending_events
                    .push_back((timestamp, record_data, pkt.len()));
                saw_events = true;
            }

            if self.count_sent != 0 && self.pkt_cnt >= self.count_sent {
                self.exhausted = true;
                self.finalize();
            }

            if !self.running.load(Ordering::SeqCst) {
                self.exhausted = true;
                self.finalize();
            }

            // Netflow flushes per-packet: once a packet produced events, keep
            // returning that packet's pending records across subsequent calls
            // until all of them have been sent.
            if saw_events {
                return Ok(self.drain_pending_batch());
            }

            if self.exhausted {
                return Ok(None);
            }
        }

        self.exhausted = true;
        self.finalize();
        Ok(self.drain_pending_batch())
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

#[cfg(test)]
mod tests {
    use std::{fs::File, io::Write};

    use anyhow::Result;
    use giganto_client::ingest::netflow::Netflow5;
    use tempfile::tempdir;

    use super::*;

    const ETHERNET_DATALINK: u32 = 1;
    const PROTO_UDP: u8 = 17;

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        let filtered: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        filtered
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    fn write_pcap(path: &Path, packets: &[Vec<u8>]) -> Result<()> {
        let mut file = File::create(path)?;

        file.write_all(&0xa1b2_c3d4_u32.to_le_bytes())?;
        file.write_all(&2u16.to_le_bytes())?;
        file.write_all(&4u16.to_le_bytes())?;
        file.write_all(&0i32.to_le_bytes())?;
        file.write_all(&0u32.to_le_bytes())?;
        file.write_all(&65_535u32.to_le_bytes())?;
        file.write_all(&ETHERNET_DATALINK.to_le_bytes())?;

        for packet in packets {
            let packet_len = u32::try_from(packet.len()).unwrap_or_default();
            file.write_all(&0u32.to_le_bytes())?;
            file.write_all(&0u32.to_le_bytes())?;
            file.write_all(&packet_len.to_le_bytes())?;
            file.write_all(&packet_len.to_le_bytes())?;
            file.write_all(packet)?;
        }

        Ok(())
    }

    fn build_ipv4_udp_packet(payload: &[u8], dst_port: u16) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0u8; 6]);
        bytes.extend_from_slice(&[1, 2, 3, 4, 5, 6]);
        bytes.extend_from_slice(&0x0800u16.to_be_bytes());

        let total_len = 20u16 + 8u16 + u16::try_from(payload.len()).unwrap_or_default();
        bytes.push(0x45);
        bytes.push(0);
        bytes.extend_from_slice(&total_len.to_be_bytes());
        bytes.extend_from_slice(&0x1234u16.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.push(64);
        bytes.push(PROTO_UDP);
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(&[10, 0, 0, 1]);
        bytes.extend_from_slice(&[10, 0, 0, 2]);

        let udp_len = 8u16 + u16::try_from(payload.len()).unwrap_or_default();
        bytes.extend_from_slice(&1000u16.to_be_bytes());
        bytes.extend_from_slice(&dst_port.to_be_bytes());
        bytes.extend_from_slice(&udp_len.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(payload);

        bytes
    }

    fn v5_header_bytes(count: u16) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&5u16.to_be_bytes());
        bytes.extend_from_slice(&count.to_be_bytes());
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(&2u32.to_be_bytes());
        bytes.extend_from_slice(&3u32.to_be_bytes());
        bytes.extend_from_slice(&4u32.to_be_bytes());
        bytes.push(5);
        bytes.push(6);
        bytes.extend_from_slice(&0x4001u16.to_be_bytes());
        bytes
    }

    fn build_v5_packet(record_count: u16) -> Vec<u8> {
        let record = hex_to_bytes(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/netflow/v5_record.hex"
        )));

        let mut payload = v5_header_bytes(record_count);
        for _ in 0..record_count {
            payload.extend_from_slice(&record);
        }

        build_ipv4_udp_packet(&payload, 2055)
    }

    #[tokio::test]
    async fn oversized_packet_keeps_remaining_records_for_next_batch() -> Result<()> {
        let temp_dir = tempdir()?;
        let pcap_path = temp_dir.path().join("oversized.pcap");
        write_pcap(
            &pcap_path,
            &[build_v5_packet(
                u16::try_from(BATCH_SIZE + 1).expect("batch size fits in u16"),
            )],
        )?;

        let running = Arc::new(AtomicBool::new(true));
        let mut collector =
            NetflowCollector::<Netflow5>::new(&pcap_path, RawEventKind::Netflow5, 0, 0, running)?;

        let first = collector
            .next_batch()
            .await?
            .expect("the oversized test packet always produces at least one batch");
        let second = collector
            .next_batch()
            .await?
            .expect("pending records from the same packet must remain buffered");

        assert_eq!(first.events.len(), BATCH_SIZE);
        assert_eq!(first.record_bytes.len(), BATCH_SIZE);
        assert_eq!(second.events.len(), 1);
        assert_eq!(second.record_bytes.len(), 1);
        assert!(collector.next_batch().await?.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn normal_packet_returns_all_records_then_exhausts() -> Result<()> {
        let temp_dir = tempdir()?;
        let pcap_path = temp_dir.path().join("normal.pcap");
        write_pcap(&pcap_path, &[build_v5_packet(2)])?;

        let running = Arc::new(AtomicBool::new(true));
        let mut collector =
            NetflowCollector::<Netflow5>::new(&pcap_path, RawEventKind::Netflow5, 0, 0, running)?;

        let batch = collector
            .next_batch()
            .await?
            .expect("the test packet contains two valid netflow records");

        assert_eq!(batch.events.len(), 2);
        assert_eq!(batch.record_bytes.len(), 2);
        assert!(collector.next_batch().await?.is_none());
        Ok(())
    }
}
