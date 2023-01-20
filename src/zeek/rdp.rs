use super::{parse_zeek_timestamp, TryFromZeekRecord};
use anyhow::{anyhow, Context, Result};
use serde::Serialize;
use std::net::IpAddr;

#[derive(Debug, Serialize)]
pub(crate) struct ZeekRdp {
    src_addr: IpAddr,
    src_port: u16,
    dst_addr: IpAddr,
    dst_port: u16,
    proto: u8,
    duration: i64,
    cookie: String,
}

impl TryFromZeekRecord for ZeekRdp {
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
        let cookie = if let Some(cookie) = rec.get(6) {
            cookie.to_string()
        } else {
            return Err(anyhow!("missing cookie"));
        };

        Ok((
            Self {
                src_addr,
                src_port,
                dst_addr,
                dst_port,
                proto: 0,
                duration: 0,
                cookie,
            },
            time,
        ))
    }
}
