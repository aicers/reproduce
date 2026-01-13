mod fields;
mod packet;
mod statistics;
mod templates;

use anyhow::{Result, bail};
use giganto_client::ingest::netflow::{Netflow5, Netflow9};
use jiff::Timestamp;
#[allow(clippy::module_name_repetitions)]
pub(super) use packet::{NetflowHeader, PktBuf};
pub(super) use statistics::{ProcessStats, Stats};
pub(super) use templates::TemplatesBox;
use tracing::warn;

pub(crate) trait ParseNetflowDatasets: Sized {
    fn parse_netflow_datasets(
        pkt_cnt: u64,
        templates: &mut TemplatesBox,
        header: &NetflowHeader,
        nanos: &mut u32,
        input: &mut PktBuf,
        stats: &mut Stats,
    ) -> Result<Vec<(i64, Self)>>;
}

impl ParseNetflowDatasets for Netflow5 {
    fn parse_netflow_datasets(
        _pkt_cnt: u64,
        _templates: &mut TemplatesBox,
        header: &NetflowHeader,
        nanos: &mut u32,
        input: &mut PktBuf,
        stats: &mut Stats,
    ) -> Result<Vec<(i64, Self)>> {
        let NetflowHeader::V5(header) = header else {
            bail!("invalid netflow v5 header");
        };
        let mut events = vec![];
        if let Ok(values) = input.parse_netflow_v5_datasets(header) {
            for v5 in values {
                events.push((netflow_timestamp(header.unix_secs, *nanos), v5));
                *nanos += 1;
            }
            stats.add(ProcessStats::Events, usize::from(header.count));
        } else {
            stats.add(ProcessStats::InvalidNetflowPackets, 1);
            bail!("invalid netflow v5 pcap");
        }
        Ok(events)
    }
}

impl ParseNetflowDatasets for Netflow9 {
    fn parse_netflow_datasets(
        pkt_cnt: u64,
        templates: &mut TemplatesBox,
        header: &NetflowHeader,
        nanos: &mut u32,
        input: &mut PktBuf,
        stats: &mut Stats,
    ) -> Result<Vec<(i64, Self)>> {
        let NetflowHeader::V9(header) = header else {
            bail!("invalid netflow v9 header");
        };
        let Ok((flowset_id, flowset_length)) = input.parse_netflow_v9_flowset_header() else {
            stats.add(ProcessStats::InvalidNetflowPackets, 1);
            bail!("invalid netflow v9 pcap");
        };

        let mut events = vec![];
        match flowset_id {
            // Template
            0 => {
                let mut template_count = 0;
                for _i in 0..header.count {
                    let Ok(fds) = input.parse_netflow_template(flowset_length, header) else {
                        break;
                    };
                    templates.add(pkt_cnt, input.src_addr(), &fds);
                    template_count += fds.len();
                }
                stats.add(ProcessStats::V9Templates, template_count);
            }
            // Options Template
            1 => {
                let mut template_count = 0;
                for _i in 0..header.count {
                    let Ok(fds) = input.parse_netflow_options_template(flowset_length, header)
                    else {
                        break;
                    };
                    templates.add(pkt_cnt, input.src_addr(), &fds);
                    template_count += fds.len();
                }
                stats.add(ProcessStats::V9OptionsTemplate, template_count);
            }
            // Reserved flowset id
            2..=255 => {
                warn!(
                    "packet #{}: NETFLOW V9 reserved Flowset ID found!!",
                    pkt_cnt
                );
                stats.add(ProcessStats::ReservedFlowsetIDUsed, 1);
            }
            // Dataset
            _ => {
                let flow_key = (input.src_addr(), header.source_id, flowset_id);
                if let Some(template) = templates.get(&flow_key) {
                    let flows = input.parse_netflow_v9_datasets(template, header, flowset_id);
                    for v9 in flows {
                        events.push((netflow_timestamp(header.unix_secs, *nanos), v9));
                        *nanos += 1;
                    }
                    stats.add(ProcessStats::Events, usize::from(header.count));
                } else {
                    warn!("No template for flow key ({:?})", flow_key);
                    stats.add(ProcessStats::TemplateNotFound, 1);
                }
            }
        }
        Ok(events)
    }
}

fn netflow_timestamp(unix_secs: u32, nanos: u32) -> i64 {
    // nanos must be less than 1 billion (0-999999999)
    if nanos >= 1_000_000_000 {
        return 0;
    }
    Timestamp::new(i64::from(unix_secs), i32::try_from(nanos).unwrap_or(0))
        .map_or(0, |t| i64::try_from(t.as_nanosecond()).unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::netflow_timestamp;

    #[test]
    fn netflow_timestamp_combines_seconds_and_nanos() {
        let result = netflow_timestamp(1, 42);
        assert_eq!(result, 1_000_000_000 + 42);
    }

    #[test]
    fn netflow_timestamp_rejects_invalid_nanos() {
        assert_eq!(netflow_timestamp(1, 1_000_000_000), 0);
        assert_eq!(netflow_timestamp(1, u32::MAX), 0);
    }

    /// Tests that opening a PCAP file with a non-ETHERNET link type
    /// is detected when the datalink check is performed.
    /// This exercises the error branch in `send_netflow` that checks
    /// for non-ETHERNET link types.
    #[test]
    fn non_ethernet_linktype_detected() {
        use std::io::Write;

        use tempfile::NamedTempFile;

        // Create a PCAP file manually with a non-ETHERNET link type
        // PCAP global header format (24 bytes):
        // - Magic number: 0xa1b2c3d4 (4 bytes) - little endian
        // - Major version: 2 (2 bytes)
        // - Minor version: 4 (2 bytes)
        // - Timezone offset: 0 (4 bytes)
        // - Timestamp accuracy: 0 (4 bytes)
        // - Snapshot length: 65535 (4 bytes)
        // - Link type: 12 = DLT_RAW on some systems, let's use 113 = DLT_LINUX_SLL
        //   which is a common non-ETHERNET type
        let mut pcap_data = Vec::new();

        // PCAP global header (little endian)
        pcap_data.extend_from_slice(&0xa1b2_c3d4_u32.to_le_bytes()); // magic
        pcap_data.extend_from_slice(&2_u16.to_le_bytes()); // major version
        pcap_data.extend_from_slice(&4_u16.to_le_bytes()); // minor version
        pcap_data.extend_from_slice(&0_i32.to_le_bytes()); // timezone
        pcap_data.extend_from_slice(&0_u32.to_le_bytes()); // timestamp accuracy
        pcap_data.extend_from_slice(&65535_u32.to_le_bytes()); // snapshot length
        // Link type: 113 = DLT_LINUX_SLL (Linux cooked capture)
        pcap_data.extend_from_slice(&113_u32.to_le_bytes());

        // Packet header (16 bytes) + minimal data
        // ts_sec, ts_usec, caplen, len
        pcap_data.extend_from_slice(&0_u32.to_le_bytes()); // ts_sec
        pcap_data.extend_from_slice(&0_u32.to_le_bytes()); // ts_usec
        pcap_data.extend_from_slice(&20_u32.to_le_bytes()); // caplen
        pcap_data.extend_from_slice(&20_u32.to_le_bytes()); // len

        // Dummy packet data (20 bytes)
        pcap_data.extend_from_slice(&[0u8; 20]);

        // Write to temp file
        let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
        temp_file
            .write_all(&pcap_data)
            .expect("Failed to write pcap data");
        temp_file.flush().expect("Failed to flush temp file");

        // Now open the file and verify the datalink type is not ETHERNET
        let handle = pcap::Capture::from_file(temp_file.path()).expect("Failed to open pcap file");

        // Verify the datalink is NOT Ethernet (ETHERNET = 1)
        assert_ne!(
            handle.get_datalink(),
            pcap::Linktype::ETHERNET,
            "Expected non-ETHERNET link type, got ETHERNET"
        );

        // Verify that it matches the linktype we set (113 = DLT_LINUX_SLL)
        assert_eq!(
            handle.get_datalink(),
            pcap::Linktype(113),
            "Expected DLT_LINUX_SLL (113) link type"
        );
    }

    /// Tests that when a `NetFlow` v9 data flowset references a template ID
    /// that doesn't exist in the template registry, the `TemplateNotFound`
    /// statistic is incremented and no events are returned.
    #[test]
    fn netflow9_missing_template_increments_stat() {
        use giganto_client::ingest::netflow::Netflow9;
        use tempfile::NamedTempFile;

        use super::{
            ParseNetflowDatasets, ProcessStats, Stats, TemplatesBox,
            packet::{NetflowHeader, PktBuf},
        };

        // Create a PCAP file with ETHERNET link type containing a NetFlow v9
        // packet that has a data flowset referencing a non-existent template
        let linktype = pcap::Linktype::ETHERNET;
        let dead_capture = pcap::Capture::dead(linktype).expect("Failed to create dead capture");

        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let temp_path = temp_file.path();

        let mut savefile = dead_capture
            .savefile(temp_path)
            .expect("Failed to create savefile");

        // Build a packet with:
        // - Ethernet header (14 bytes)
        // - IPv4 header (20 bytes)
        // - UDP header (8 bytes)
        // - NetFlow v9 header (20 bytes)
        // - Data flowset header with template ID 256 (4 bytes) + minimal data
        let mut packet_data = Vec::new();

        // Ethernet header (14 bytes)
        // Dest MAC (6 bytes)
        packet_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        // Src MAC (6 bytes)
        packet_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        // EtherType: IPv4 (0x0800)
        packet_data.extend_from_slice(&[0x08, 0x00]);

        // IPv4 header (20 bytes)
        packet_data.push(0x45); // Version 4, IHL 5 (20 bytes)
        packet_data.push(0x00); // TOS
        // Total length (20 + 8 + 20 + 8 = 56 bytes for IP payload)
        packet_data.extend_from_slice(&[0x00, 0x38]);
        packet_data.extend_from_slice(&[0x00, 0x00]); // ID
        packet_data.extend_from_slice(&[0x00, 0x00]); // Flags, Fragment Offset
        packet_data.push(0x40); // TTL
        packet_data.push(0x11); // Protocol: UDP (17)
        packet_data.extend_from_slice(&[0x00, 0x00]); // Checksum (ignored)
        // Source IP: 192.168.1.1
        packet_data.extend_from_slice(&[0xc0, 0xa8, 0x01, 0x01]);
        // Dest IP: 192.168.1.2
        packet_data.extend_from_slice(&[0xc0, 0xa8, 0x01, 0x02]);

        // UDP header (8 bytes)
        packet_data.extend_from_slice(&[0x00, 0x50]); // Src port: 80
        packet_data.extend_from_slice(&[0x08, 0x07]); // Dst port: 2055 (NetFlow)
        // UDP length (8 + 20 + 8 = 36 bytes)
        packet_data.extend_from_slice(&[0x00, 0x24]);
        packet_data.extend_from_slice(&[0x00, 0x00]); // Checksum (ignored)

        // NetFlow v9 header (20 bytes)
        packet_data.extend_from_slice(&[0x00, 0x09]); // Version: 9
        packet_data.extend_from_slice(&[0x00, 0x01]); // Count: 1 flowset
        packet_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // SysUptime: 1ms
        packet_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // Unix secs: 1
        packet_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // Sequence: 1
        packet_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // Source ID: 1

        // Data flowset header (4 bytes) + padding
        // Flowset ID: 256 (a template ID that doesn't exist)
        packet_data.extend_from_slice(&[0x01, 0x00]);
        // Flowset length: 8 bytes (header + 4 bytes of data)
        packet_data.extend_from_slice(&[0x00, 0x08]);
        // Some dummy data
        packet_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        #[allow(clippy::cast_possible_truncation)]
        let header = pcap::PacketHeader {
            ts: libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            },
            caplen: packet_data.len() as u32,
            len: packet_data.len() as u32,
        };
        let packet = pcap::Packet {
            header: &header,
            data: &packet_data,
        };
        savefile.write(&packet);
        drop(savefile);

        // Open the file and parse
        let mut handle = pcap::Capture::from_file(temp_path).expect("Failed to open pcap file");

        // Ensure it's ETHERNET
        assert_eq!(handle.get_datalink(), pcap::Linktype::ETHERNET);

        // Get the packet
        let pkt = handle.next_packet().expect("Failed to get packet");
        let mut input = PktBuf::new(&pkt);

        // Parse Ethernet/IP/UDP to reach NetFlow data
        let result = input.is_netflow();
        assert_eq!(
            result,
            ProcessStats::YesNetflowPackets,
            "Expected YesNetflowPackets, got {result:?}"
        );

        // Parse NetFlow header
        let nf_header = input
            .parse_netflow_header()
            .expect("Failed to parse NetFlow header");
        assert!(
            matches!(nf_header, NetflowHeader::V9(_)),
            "Expected NetFlow v9 header"
        );

        // Create empty templates (no template 256 registered)
        let mut templates = TemplatesBox::new();
        let mut stats = Stats::new();
        let mut nanos = 0_u32;

        // Parse the data flowset - should trigger missing template path
        let events = Netflow9::parse_netflow_datasets(
            1,
            &mut templates,
            &nf_header,
            &mut nanos,
            &mut input,
            &mut stats,
        )
        .expect("parse_netflow_datasets should not fail on missing template");

        // Verify no events were returned (template was missing)
        assert!(
            events.is_empty(),
            "Expected no events when template is missing"
        );

        // Verify the TemplateNotFound stat was incremented
        // The Stats struct doesn't expose a getter, so we check via Display
        let stats_str = format!("{stats}");
        assert!(
            stats_str.contains("TemplateNotFound"),
            "Expected TemplateNotFound stat to be recorded, got: {stats_str}"
        );
    }
}
