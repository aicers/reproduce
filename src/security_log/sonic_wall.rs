use std::{net::IpAddr, str::FromStr, sync::OnceLock};

use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, FixedOffset};
use giganto_client::ingest::log::SecuLog;
use regex::Regex;

use super::{
    proto_to_u8, ParseSecurityLog, SecurityLogInfo, SonicWall, DEFAULT_IPADDR, DEFAULT_PORT,
};

fn get_sonic_regex() -> &'static Regex {
    static LOG_REGEX: OnceLock<Regex> = OnceLock::new();

    LOG_REGEX.get_or_init(|| {
        Regex::new(r#"time="(?<datetime>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) .*?src=(?<srcIp>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(?<srcPort>\d+):.*? dst=(?<dstIp>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(?<dstPort>\d+).*?proto=(?<proto>\w+)\/"#)
            .expect("regex")
    })
}

fn parse_sonic_timestamp(datetime: &str) -> Result<DateTime<FixedOffset>> {
    DateTime::parse_from_str(&format!("{datetime} +0900"), "%Y-%m-%d %H:%M:%S %z")
        .map_err(|e| anyhow!("{e:?}"))
}

impl ParseSecurityLog for SonicWall {
    fn parse_security_log(
        line: &str,
        serial: i64,
        info: SecurityLogInfo,
    ) -> Result<(SecuLog, i64)> {
        let caps = get_sonic_regex()
            .captures(line)
            .context("invalid log line")?;

        let datetime = match caps.name("datetime") {
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
            Some(d) => d.as_str(),
            None => "TCP",
        };

        let timestamp = parse_sonic_timestamp(datetime)?
            .timestamp_nanos_opt()
            .context("to_timestamp_nanos")?
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
                proto: Some(proto_to_u8(proto)),
                contents: line.to_string(),
            },
            timestamp,
        ))
    }
}
