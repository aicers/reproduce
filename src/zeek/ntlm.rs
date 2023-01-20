use super::{parse_zeek_timestamp, TryFromZeekRecord};
use anyhow::{anyhow, Context, Result};
use serde::Serialize;
use std::net::IpAddr;

#[derive(Debug, Serialize)]
pub(crate) struct ZeekNtlm {
    src_addr: IpAddr,
    src_port: u16,
    dst_addr: IpAddr,
    dst_port: u16,
    proto: u8,
    duration: i64,
    username: String,
    hostname: String,
    domainname: String,
    server_nb_computer_name: String,
    server_dns_computer_name: String,
    server_tree_name: String,
    success: String,
}

impl TryFromZeekRecord for ZeekNtlm {
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
        let username = if let Some(username) = rec.get(6) {
            username.to_string()
        } else {
            return Err(anyhow!("missing username"));
        };
        let hostname = if let Some(hostname) = rec.get(7) {
            hostname.to_string()
        } else {
            return Err(anyhow!("missing hostname"));
        };
        let domainname = if let Some(domainname) = rec.get(8) {
            domainname.to_string()
        } else {
            return Err(anyhow!("missing domainname"));
        };
        let server_nb_computer_name = if let Some(server_nb_computer_name) = rec.get(9) {
            server_nb_computer_name.to_string()
        } else {
            return Err(anyhow!("missing server_nb_computer_name"));
        };
        let server_dns_computer_name = if let Some(server_dns_computer_name) = rec.get(10) {
            server_dns_computer_name.to_string()
        } else {
            return Err(anyhow!("missing server_dns_computer_name"));
        };
        let server_tree_name = if let Some(server_tree_name) = rec.get(11) {
            server_tree_name.to_string()
        } else {
            return Err(anyhow!("missing server_tree_name"));
        };
        let success = if let Some(success) = rec.get(12) {
            success.to_string()
        } else {
            return Err(anyhow!("missing success"));
        };

        Ok((
            Self {
                src_addr,
                src_port,
                dst_addr,
                dst_port,
                proto: 0,
                duration: 0,
                username,
                hostname,
                domainname,
                server_nb_computer_name,
                server_dns_computer_name,
                server_tree_name,
                success,
            },
            time,
        ))
    }
}
