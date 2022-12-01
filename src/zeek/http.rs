use super::{parse_zeek_timestamp, TryFromZeekRecord};
use anyhow::{anyhow, Context, Result};
use serde::Serialize;
use std::net::IpAddr;

#[derive(Debug, Serialize)]
pub(crate) struct ZeekHttp {
    src_addr: IpAddr,
    dst_addr: IpAddr,
    src_port: u16,
    dst_port: u16,
    method: String,
    host: String,
    uri: String,
    referrer: String,
    user_agent: String,
    status_code: u16,
}

impl TryFromZeekRecord for ZeekHttp {
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
        let method = if let Some(method) = rec.get(7) {
            method.to_string()
        } else {
            return Err(anyhow!("missing method"));
        };
        let host = if let Some(host) = rec.get(8) {
            host.to_string()
        } else {
            return Err(anyhow!("missing host"));
        };
        let uri = if let Some(uri) = rec.get(9) {
            uri.to_string()
        } else {
            return Err(anyhow!("missing uri"));
        };
        let referrer = if let Some(referrer) = rec.get(10) {
            referrer.to_string()
        } else {
            return Err(anyhow!("missing referrer"));
        };
        let user_agent = if let Some(user_agent) = rec.get(12) {
            user_agent.to_string()
        } else {
            return Err(anyhow!("missing user_agent"));
        };
        let status_code = if let Some(status_code) = rec.get(16) {
            if status_code.eq("-") {
                0
            } else {
                status_code.parse::<u16>().context("invalid status code")?
            }
        } else {
            return Err(anyhow!("missing status code"));
        };

        Ok((
            Self {
                src_addr,
                dst_addr,
                src_port,
                dst_port,
                method,
                host,
                uri,
                referrer,
                user_agent,
                status_code,
            },
            time,
        ))
    }
}
