use super::{parse_zeek_timestamp, TryFromZeekRecord, PROTO_ICMP, PROTO_TCP, PROTO_UDP};
use anyhow::{anyhow, Context, Result};
use num_traits::ToPrimitive;
use serde::Serialize;
use std::net::IpAddr;

#[derive(Debug, Serialize)]
pub(crate) struct ZeekConn {
    src_addr: IpAddr,
    dst_addr: IpAddr,
    src_port: u16,
    dst_port: u16,
    proto: u8,
    service: String,
    duration: i64,
    orig_bytes: u64,
    resp_bytes: u64,
    orig_pkts: u64,
    resp_pkts: u64,
}

impl TryFromZeekRecord for ZeekConn {
    #[allow(clippy::too_many_lines)]
    fn try_from_zeek_record(rec: &csv::StringRecord) -> Result<(Self, i64)> {
        let time = if let Some(timestamp) = rec.get(0) {
            parse_zeek_timestamp(timestamp)?.timestamp_nanos()
        } else {
            return Err(anyhow!("missing timestamp"));
        };
        let src_addr = if let Some(src_addr) = rec.get(2) {
            src_addr
                .parse::<IpAddr>()
                .context("invalid source address")?
        } else {
            return Err(anyhow!("missing source address"));
        };
        let src_port = if let Some(src_port) = rec.get(3) {
            src_port.parse::<u16>().context("invalid source port")?
        } else {
            return Err(anyhow!("missing source port"));
        };
        let dst_addr = if let Some(dst_addr) = rec.get(4) {
            dst_addr
                .parse::<IpAddr>()
                .context("invalid destination address")?
        } else {
            return Err(anyhow!("missing destination address"));
        };
        let dst_port = if let Some(dst_port) = rec.get(5) {
            dst_port
                .parse::<u16>()
                .context("invalid destination port")?
        } else {
            return Err(anyhow!("missing destination port"));
        };
        let proto = if let Some(proto) = rec.get(6) {
            match proto {
                "tcp" => PROTO_TCP,
                "udp" => PROTO_UDP,
                "icmp" => PROTO_ICMP,
                _ => 0,
            }
        } else {
            return Err(anyhow!("missing protocol"));
        };
        let service = if let Some(service) = rec.get(7) {
            service.to_string()
        } else {
            return Err(anyhow!("missing service"));
        };
        let duration = if let Some(duration) = rec.get(8) {
            if duration.eq("-") {
                0
            } else {
                ((duration.parse::<f64>().context("invalid duration")? * 1_000_000_000.0).round())
                    .to_i64()
                    .expect("valid")
            }
        } else {
            return Err(anyhow!("missing duration"));
        };
        let orig_bytes = if let Some(orig_bytes) = rec.get(9) {
            if orig_bytes.eq("-") {
                0
            } else {
                orig_bytes.parse::<u64>().context("invalid source bytes")?
            }
        } else {
            return Err(anyhow!("missing source bytes"));
        };
        let resp_bytes = if let Some(resp_bytes) = rec.get(10) {
            if resp_bytes.eq("-") {
                0
            } else {
                resp_bytes
                    .parse::<u64>()
                    .context("invalid destination bytes")?
            }
        } else {
            return Err(anyhow!("missing destination bytes"));
        };
        let orig_pkts = if let Some(orig_pkts) = rec.get(16) {
            if orig_pkts.eq("-") {
                0
            } else {
                orig_pkts.parse::<u64>().context("invalid source packets")?
            }
        } else {
            return Err(anyhow!("missing source packets"));
        };
        let resp_pkts = if let Some(resp_pkts) = rec.get(18) {
            if resp_pkts.eq("-") {
                0
            } else {
                resp_pkts
                    .parse::<u64>()
                    .context("invalid destination packets")?
            }
        } else {
            return Err(anyhow!("missing destination packets"));
        };

        Ok((
            Self {
                src_addr,
                dst_addr,
                src_port,
                dst_port,
                proto,
                service,
                duration,
                orig_bytes,
                resp_bytes,
                orig_pkts,
                resp_pkts,
            },
            time,
        ))
    }
}
