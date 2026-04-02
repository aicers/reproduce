use std::{collections::VecDeque, env, fmt::Debug, marker::PhantomData, path::Path};

use async_trait::async_trait;
use giganto_client::RawEventKind;
use serde::Serialize;
use tokio::sync::watch;
use tracing::error;

use super::{CollectedBatch, Collector, CollectorResult, position_bytes, shutdown_requested};
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
    shutdown: watch::Receiver<bool>,
    templates: TemplatesBox,
    tmpl_path: Option<String>,
    stats: Stats,
    pkt_cnt: u64,
    committed_pkt_cnt: u64,
    pending_commit: Option<u64>,
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
        shutdown: watch::Receiver<bool>,
    ) -> CollectorResult<Self> {
        let tmpl_path = env::var("NETFLOW_TEMPLATES_PATH").ok();
        let templates = if let Some(ref path) = tmpl_path {
            TemplatesBox::from_path(path).unwrap_or_default()
        } else {
            TemplatesBox::new()
        };

        let handle = pcap::Capture::from_file(filename).map_err(anyhow::Error::from)?;
        if handle.get_datalink() != pcap::Linktype::ETHERNET {
            return Err(anyhow::anyhow!(
                "Error: unknown datalink {:?} in {}",
                handle.get_datalink().get_name(),
                filename.display()
            )
            .into());
        }

        Ok(Self {
            handle,
            protocol,
            skip,
            count_sent,
            shutdown,
            templates,
            tmpl_path,
            stats: Stats::new(),
            pkt_cnt: 0,
            committed_pkt_cnt: skip,
            pending_commit: None,
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

    /// Returns the number of processed packets for compatibility with legacy
    /// collector statistics.
    #[must_use]
    pub fn stats(&self) -> (u64, u64) {
        (self.pkt_cnt, 0)
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
            kind: self.protocol,
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
    #[allow(clippy::too_many_lines)]
    async fn next_batch(&mut self) -> CollectorResult<Option<CollectedBatch>> {
        if self.pending_events.is_empty()
            && let Some(position) = self.pending_commit.take()
        {
            self.committed_pkt_cnt = position;
        }

        if let Some(batch) = self.drain_pending_batch() {
            return Ok(Some(batch));
        }

        if self.exhausted {
            self.finalize();
            self.committed_pkt_cnt = self.pkt_cnt;
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
                let record_data = bincode::serialize(&event).map_err(anyhow::Error::from)?;
                self.pending_events
                    .push_back((timestamp, record_data, pkt.len()));
                saw_events = true;
            }

            if self.count_sent != 0 && self.pkt_cnt >= self.count_sent {
                self.exhausted = true;
                self.finalize();
            }

            if shutdown_requested(&self.shutdown) {
                self.exhausted = true;
                self.finalize();
            }

            // Netflow flushes per-packet: once a packet produced events, keep
            // returning that packet's pending records across subsequent calls
            // until all of them have been sent.
            if saw_events {
                self.pending_commit = Some(self.pkt_cnt);
                return Ok(self.drain_pending_batch());
            }

            if self.exhausted {
                self.committed_pkt_cnt = self.pkt_cnt;
                return Ok(None);
            }
        }

        self.exhausted = true;
        self.finalize();
        if self.pending_events.is_empty() {
            self.committed_pkt_cnt = self.pkt_cnt;
        }
        Ok(self.drain_pending_batch())
    }

    fn position(&self) -> Vec<u8> {
        position_bytes(self.committed_pkt_cnt)
    }
}

#[cfg(test)]
mod tests {
    use std::{env, fs::File, io::Write, sync::Mutex};

    use anyhow::Result;
    use giganto_client::ingest::netflow::{Netflow5, Netflow9};
    use tempfile::tempdir;
    use tokio::sync::watch;

    use super::*;

    const ETHERNET_DATALINK: u32 = 1;
    const RAW_DATALINK: u32 = 101;
    const NETFLOW_TEMPLATES_ENV: &str = "NETFLOW_TEMPLATES_PATH";
    const NETFLOW_UDP_PORT: u16 = 2055;
    const PROTO_UDP: u8 = 17;
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvVarGuard {
        previous: Option<String>,
    }

    impl EnvVarGuard {
        fn set(path: &str) -> Self {
            let previous = env::var(NETFLOW_TEMPLATES_ENV).ok();
            unsafe {
                env::set_var(NETFLOW_TEMPLATES_ENV, path);
            }
            Self { previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(previous) = self.previous.take() {
                unsafe {
                    env::set_var(NETFLOW_TEMPLATES_ENV, previous);
                }
            } else {
                unsafe {
                    env::remove_var(NETFLOW_TEMPLATES_ENV);
                }
            }
        }
    }

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        let filtered: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        filtered
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    fn write_pcap_with_datalink(path: &Path, packets: &[Vec<u8>], datalink: u32) -> Result<()> {
        let mut file = File::create(path)?;

        file.write_all(&0xa1b2_c3d4_u32.to_le_bytes())?;
        file.write_all(&2u16.to_le_bytes())?;
        file.write_all(&4u16.to_le_bytes())?;
        file.write_all(&0i32.to_le_bytes())?;
        file.write_all(&0u32.to_le_bytes())?;
        file.write_all(&65_535u32.to_le_bytes())?;
        file.write_all(&datalink.to_le_bytes())?;

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

    fn write_pcap(path: &Path, packets: &[Vec<u8>]) -> Result<()> {
        write_pcap_with_datalink(path, packets, ETHERNET_DATALINK)
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

        build_ipv4_udp_packet(&payload, NETFLOW_UDP_PORT)
    }

    fn build_v9_template_packet() -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&9u16.to_be_bytes());
        payload.extend_from_slice(&1u16.to_be_bytes());
        payload.extend_from_slice(&0u32.to_be_bytes());
        payload.extend_from_slice(&0u32.to_be_bytes());
        payload.extend_from_slice(&1u32.to_be_bytes());
        payload.extend_from_slice(&1u32.to_be_bytes());
        payload.extend_from_slice(&0u16.to_be_bytes());
        payload.extend_from_slice(&16u16.to_be_bytes());
        payload.extend_from_slice(&256u16.to_be_bytes());
        payload.extend_from_slice(&2u16.to_be_bytes());
        payload.extend_from_slice(&8u16.to_be_bytes());
        payload.extend_from_slice(&4u16.to_be_bytes());
        payload.extend_from_slice(&12u16.to_be_bytes());
        payload.extend_from_slice(&4u16.to_be_bytes());
        build_ipv4_udp_packet(&payload, NETFLOW_UDP_PORT)
    }

    fn make_collector_with_options(
        path: &Path,
        count_sent: u64,
        shutdown: watch::Receiver<bool>,
    ) -> Result<NetflowCollector<Netflow5>> {
        Ok(NetflowCollector::<Netflow5>::new(
            path,
            RawEventKind::Netflow5,
            0,
            count_sent,
            shutdown,
        )?)
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

        let (_tx, shutdown) = watch::channel(false);
        let mut collector =
            NetflowCollector::<Netflow5>::new(&pcap_path, RawEventKind::Netflow5, 0, 0, shutdown)?;

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

        let (_tx, shutdown) = watch::channel(false);
        let mut collector =
            NetflowCollector::<Netflow5>::new(&pcap_path, RawEventKind::Netflow5, 0, 0, shutdown)?;

        let batch = collector
            .next_batch()
            .await?
            .expect("the test packet contains two valid netflow records");

        assert_eq!(batch.events.len(), 2);
        assert_eq!(batch.record_bytes.len(), 2);
        assert!(collector.next_batch().await?.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn invalid_and_non_netflow_packets_are_skipped_before_valid_data() -> Result<()> {
        let temp_dir = tempdir()?;
        let pcap_path = temp_dir.path().join("mixed.pcap");
        let truncated_payload = build_ipv4_udp_packet(&[0x00, 0x05], NETFLOW_UDP_PORT);
        let non_netflow_payload = build_ipv4_udp_packet(&v5_header_bytes(1), 9999);
        write_pcap(
            &pcap_path,
            &[non_netflow_payload, truncated_payload, build_v5_packet(1)],
        )?;

        let (_tx, shutdown) = watch::channel(false);
        let mut collector = make_collector_with_options(&pcap_path, 0, shutdown)?;

        let batch = collector
            .next_batch()
            .await?
            .expect("collector should eventually emit the valid netflow packet");
        assert_eq!(batch.events.len(), 1);
        assert!(collector.next_batch().await?.is_none());

        let rendered = format!("{}", collector.netflow_stats());
        assert!(rendered.contains("NoNetflowPackets = 1"));
        assert!(rendered.contains("InvalidNetflowPackets = 1"));
        assert!(rendered.contains("Packets = 3"));
        Ok(())
    }

    #[tokio::test]
    async fn invalid_netflow_packets_advance_checkpoint() -> Result<()> {
        let temp_dir = tempdir()?;
        let pcap_path = temp_dir.path().join("invalid-only.pcap");
        let truncated_payload = build_ipv4_udp_packet(&[0x00, 0x05], NETFLOW_UDP_PORT);
        let non_netflow_payload = build_ipv4_udp_packet(&v5_header_bytes(1), 9999);
        let packets = (0..=BATCH_SIZE)
            .map(|index| {
                if index % 2 == 0 {
                    non_netflow_payload.clone()
                } else {
                    truncated_payload.clone()
                }
            })
            .collect::<Vec<_>>();
        write_pcap(&pcap_path, &packets)?;

        let (_tx, shutdown) = watch::channel(false);
        let mut collector = make_collector_with_options(&pcap_path, 0, shutdown)?;

        assert!(collector.next_batch().await?.is_none());
        assert_eq!(
            collector.position(),
            format!("{}", BATCH_SIZE + 1).into_bytes()
        );
        Ok(())
    }

    #[tokio::test]
    async fn skip_beyond_packet_count_caps_checkpoint_to_actual_packets() -> Result<()> {
        let temp_dir = tempdir()?;
        let pcap_path = temp_dir.path().join("skip-too-large.pcap");
        write_pcap(&pcap_path, &[build_v5_packet(1), build_v5_packet(1)])?;

        let (_tx, shutdown) = watch::channel(false);
        let mut collector =
            NetflowCollector::<Netflow5>::new(&pcap_path, RawEventKind::Netflow5, 10, 0, shutdown)?;

        assert!(collector.next_batch().await?.is_none());
        assert_eq!(collector.position(), b"2".to_vec());
        Ok(())
    }

    #[tokio::test]
    async fn invalid_netflow_packets_after_full_batch_advance_checkpoint() -> Result<()> {
        let temp_dir = tempdir()?;
        let pcap_path = temp_dir.path().join("invalid-tail.pcap");
        let mut packets = vec![build_v5_packet(
            u16::try_from(BATCH_SIZE).expect("batch size fits in u16"),
        )];
        packets.push(build_ipv4_udp_packet(&[0x00, 0x05], NETFLOW_UDP_PORT));
        write_pcap(&pcap_path, &packets)?;

        let (_tx, shutdown) = watch::channel(false);
        let mut collector = make_collector_with_options(&pcap_path, 0, shutdown)?;

        let batch = collector
            .next_batch()
            .await?
            .expect("collector should flush the first full batch");
        assert_eq!(batch.events.len(), BATCH_SIZE);
        assert!(collector.next_batch().await?.is_none());
        assert_eq!(collector.position(), b"2".to_vec());
        Ok(())
    }

    #[tokio::test]
    async fn count_sent_stops_netflow_processing_after_first_packet() -> Result<()> {
        let temp_dir = tempdir()?;
        let pcap_path = temp_dir.path().join("count-sent.pcap");
        write_pcap(&pcap_path, &[build_v5_packet(1), build_v5_packet(1)])?;

        let (_tx, shutdown) = watch::channel(false);
        let mut collector = make_collector_with_options(&pcap_path, 1, shutdown)?;

        let batch = collector
            .next_batch()
            .await?
            .expect("collector should emit the first packet before exhausting");
        assert_eq!(batch.events.len(), 1);
        assert_eq!(batch.kind, RawEventKind::Netflow5);
        assert!(collector.next_batch().await?.is_none());
        assert_eq!(collector.position(), b"1".to_vec());
        Ok(())
    }

    #[tokio::test]
    async fn stopped_netflow_collector_flushes_current_packet_then_exhausts() -> Result<()> {
        let temp_dir = tempdir()?;
        let pcap_path = temp_dir.path().join("stopped.pcap");
        write_pcap(&pcap_path, &[build_v5_packet(1)])?;

        let (_tx, shutdown) = watch::channel(true);
        let mut collector = make_collector_with_options(&pcap_path, 0, shutdown)?;

        let batch = collector
            .next_batch()
            .await?
            .expect("collector should flush records already parsed from the current packet");
        assert_eq!(batch.events.len(), 1);
        assert!(collector.next_batch().await?.is_none());
        Ok(())
    }

    #[test]
    fn new_rejects_non_ethernet_pcaps() -> Result<()> {
        let temp_dir = tempdir()?;
        let pcap_path = temp_dir.path().join("raw-linktype.pcap");
        write_pcap_with_datalink(&pcap_path, &[build_v5_packet(1)], RAW_DATALINK)?;

        let err = NetflowCollector::<Netflow5>::new(
            &pcap_path,
            RawEventKind::Netflow5,
            0,
            0,
            watch::channel(false).1,
        )
        .err()
        .expect("non-Ethernet captures must be rejected");
        assert!(err.to_string().contains("unknown datalink"));
        Ok(())
    }

    #[test]
    fn invalid_template_cache_path_falls_back_to_empty_templates() -> Result<()> {
        let _env_lock = ENV_LOCK
            .lock()
            .expect("template env lock should be acquired");
        let temp_dir = tempdir()?;
        let cache_path = temp_dir.path().join("invalid-templates.bin");
        std::fs::write(&cache_path, b"invalid template cache")?;
        let _env_guard = EnvVarGuard::set(
            cache_path
                .to_str()
                .expect("template cache fixture path must be valid UTF-8"),
        );
        let pcap_path = temp_dir.path().join("packet.pcap");
        write_pcap(&pcap_path, &[build_v5_packet(1)])?;

        let collector = NetflowCollector::<Netflow5>::new(
            &pcap_path,
            RawEventKind::Netflow5,
            0,
            0,
            watch::channel(false).1,
        )?;
        assert!(collector.templates.is_empty());
        Ok(())
    }

    #[test]
    fn v9_templates_are_persisted_when_cache_path_is_configured() -> Result<()> {
        let _env_lock = ENV_LOCK
            .lock()
            .expect("template env lock should be acquired");
        let temp_dir = tempdir()?;
        let cache_path = temp_dir.path().join("templates.bin");
        let _env_guard = EnvVarGuard::set(
            cache_path
                .to_str()
                .expect("template cache path must be valid UTF-8"),
        );
        let pcap_path = temp_dir.path().join("template-flowset.pcap");
        write_pcap(&pcap_path, &[build_v9_template_packet()])?;

        let mut collector = NetflowCollector::<Netflow9>::new(
            &pcap_path,
            RawEventKind::Netflow9,
            0,
            0,
            watch::channel(false).1,
        )?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread runtime should build");

        let batch = runtime.block_on(async { collector.next_batch().await })?;
        assert!(batch.is_none());
        assert_eq!(collector.stats(), (1, 0));
        assert!(!collector.templates.is_empty());
        assert!(cache_path.exists());
        assert!(!std::fs::read(&cache_path)?.is_empty());
        Ok(())
    }

    #[test]
    fn template_cache_write_failures_do_not_abort_collection() -> Result<()> {
        let _env_lock = ENV_LOCK
            .lock()
            .expect("template env lock should be acquired");
        let temp_dir = tempdir()?;
        let _env_guard = EnvVarGuard::set(
            temp_dir
                .path()
                .to_str()
                .expect("template cache directory must be valid UTF-8"),
        );
        let pcap_path = temp_dir.path().join("template-flowset.pcap");
        write_pcap(&pcap_path, &[build_v9_template_packet()])?;

        let mut collector = NetflowCollector::<Netflow9>::new(
            &pcap_path,
            RawEventKind::Netflow9,
            0,
            0,
            watch::channel(false).1,
        )?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread runtime should build");

        let batch = runtime.block_on(async { collector.next_batch().await })?;
        assert!(batch.is_none());
        assert_eq!(collector.stats(), (1, 0));
        assert!(!collector.templates.is_empty());
        Ok(())
    }
}
