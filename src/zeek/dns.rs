use super::{parse_zeek_timestamp, TryFromZeekRecord, PROTO_ICMP, PROTO_TCP, PROTO_UDP};
use anyhow::{anyhow, Context, Result};
use serde::Serialize;
use std::net::IpAddr;

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Serialize)]
pub(crate) struct ZeekDns {
    src_addr: IpAddr,
    src_port: u16,
    dst_addr: IpAddr,
    dst_port: u16,
    proto: u8,
    duration: i64,
    query: String,
    answer: Vec<String>,
    trans_id: u16,
    rtt: i64,
    qclass: u16,
    qtype: u16,
    rcode: u16,
    aa_flag: bool,
    tc_flag: bool,
    rd_flag: bool,
    ra_flag: bool,
    ttl: Vec<i32>,
}

impl TryFromZeekRecord for ZeekDns {
    #[allow(
        clippy::similar_names,
        clippy::cast_possible_truncation,
        clippy::too_many_lines
    )]
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
        let query = if let Some(query) = rec.get(9) {
            query.to_string()
        } else {
            return Err(anyhow!("missing query"));
        };
        let answer = if let Some(answer) = rec.get(21) {
            answer
                .split(',')
                .map(std::string::ToString::to_string)
                .collect()
        } else {
            return Err(anyhow!("missing answer"));
        };
        let trans_id = if let Some(trans_id) = rec.get(7) {
            if trans_id.eq("-") {
                0
            } else {
                trans_id.parse::<u16>().context("invalid trans_id")?
            }
        } else {
            return Err(anyhow!("missing trans_id"));
        };
        let rtt = if let Some(rtt) = rec.get(8) {
            if rtt.eq("-") {
                0
            } else {
                parse_zeek_timestamp(rtt)?.timestamp_nanos()
            }
        } else {
            return Err(anyhow!("missing rtt"));
        };
        let qclass = if let Some(qclass) = rec.get(10) {
            if qclass.eq("-") {
                0
            } else {
                qclass.parse::<u16>().context("invalid qclass")?
            }
        } else {
            return Err(anyhow!("missing qclass"));
        };
        let qtype = if let Some(qtype) = rec.get(12) {
            if qtype.eq("-") {
                0
            } else {
                qtype.parse::<u16>().context("invalid qtype")?
            }
        } else {
            return Err(anyhow!("missing qtype"));
        };
        let rcode = if let Some(rcode) = rec.get(14) {
            if rcode.eq("-") {
                0
            } else {
                rcode.parse::<u16>().context("rcode")?
            }
        } else {
            return Err(anyhow!("missing rcode"));
        };
        let aa_flag = if let Some(aa) = rec.get(16) {
            if aa.eq("T") {
                true
            } else if aa.eq("F") {
                false
            } else {
                return Err(anyhow!("invalid aa_flag"));
            }
        } else {
            return Err(anyhow!("missing aa_flag"));
        };
        let tc_flag = if let Some(tc) = rec.get(17) {
            if tc.eq("T") {
                true
            } else if tc.eq("F") {
                false
            } else {
                return Err(anyhow!("invalid tc_flag"));
            }
        } else {
            return Err(anyhow!("missing tc_flag"));
        };
        let rd_flag = if let Some(rd) = rec.get(18) {
            if rd.eq("T") {
                true
            } else if rd.eq("F") {
                false
            } else {
                return Err(anyhow!("invalid rd_flag"));
            }
        } else {
            return Err(anyhow!("missing rd_flag"));
        };
        let ra_flag = if let Some(ra) = rec.get(19) {
            if ra.eq("T") {
                true
            } else if ra.eq("F") {
                false
            } else {
                return Err(anyhow!("invalid ra_flag"));
            }
        } else {
            return Err(anyhow!("missing ra_flag"));
        };
        let ttl = if let Some(ttl) = rec.get(22) {
            if ttl.eq("-") {
                vec![0]
            } else {
                ttl.split(',')
                    .map(|t| t.parse::<f32>().unwrap() as i32)
                    .collect()
            }
        } else {
            return Err(anyhow!("missing ttl"));
        };
        Ok((
            Self {
                src_addr,
                src_port,
                dst_addr,
                dst_port,
                proto,
                duration: rtt,
                query,
                answer,
                trans_id,
                rtt,
                qclass,
                qtype,
                rcode,
                aa_flag,
                tc_flag,
                rd_flag,
                ra_flag,
                ttl,
            },
            time,
        ))
    }
}
