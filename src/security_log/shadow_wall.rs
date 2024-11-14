use std::{net::IpAddr, str::FromStr, sync::OnceLock};

use anyhow::{bail, Context, Result};
use giganto_client::ingest::log::SecuLog;
use regex::Regex;

use super::{
    ParseSecurityLog, SecurityLogInfo, ShadowWall, DEFAULT_IPADDR, DEFAULT_PORT, PROTO_TCP,
};

fn get_shadow_regex() -> &'static Regex {
    static LOG_REGEX: OnceLock<Regex> = OnceLock::new();

    LOG_REGEX.get_or_init(|| {
        Regex::new(r"(?<timestamp>\d{10}).*?(?<proto>\d+)\t(?<srcIp>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\t(?<srcPort>\d+)\t(?<dstIp>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\t(?<dstPort>\d+)")
            .expect("regex")
    })
}

impl ParseSecurityLog for ShadowWall {
    fn parse_security_log(
        line: &str,
        serial: i64,
        info: SecurityLogInfo,
    ) -> Result<(SecuLog, i64)> {
        let caps = get_shadow_regex()
            .captures(line)
            .context("invalid log line")?;

        let timestamp = match caps.name("timestamp") {
            Some(d) => d.as_str(),
            None => bail!("invalid datetime"),
        };

        let orig_addr = match caps.name("srcIp") {
            Some(d) => IpAddr::from_str(d.as_str()).unwrap_or(DEFAULT_IPADDR),
            None => DEFAULT_IPADDR,
        };

        let orig_port = match caps.name("srcPort") {
            Some(d) => d.as_str().parse::<u16>().unwrap_or_default(),
            None => DEFAULT_PORT,
        };

        let resp_addr = match caps.name("dstIp") {
            Some(d) => IpAddr::from_str(d.as_str()).unwrap_or(DEFAULT_IPADDR),
            None => DEFAULT_IPADDR,
        };

        let resp_port = match caps.name("dstPort") {
            Some(d) => d.as_str().parse::<u16>().unwrap_or_default(),
            None => DEFAULT_PORT,
        };

        let proto = match caps.name("proto") {
            Some(d) => d.as_str().parse::<u8>().unwrap_or(PROTO_TCP),
            None => PROTO_TCP,
        };

        let timestamp = format!("{timestamp}000000000")
            .parse::<i64>()
            .unwrap_or_default()
            + serial;

        Ok((
            SecuLog {
                kind: info.kind,
                log_type: info.log_type,
                version: info.version,
                orig_addr: Some(orig_addr),
                orig_port: Some(orig_port),
                resp_addr: Some(resp_addr),
                resp_port: Some(resp_port),
                proto: Some(proto),
                contents: line.to_string(),
            },
            timestamp,
        ))
    }
}
