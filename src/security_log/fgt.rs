use std::{net::IpAddr, str::FromStr, sync::OnceLock};

use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, FixedOffset};
use giganto_client::ingest::log::SecuLog;
use regex::Regex;

use super::{Fgt, ParseSecurityLog, SecurityLogInfo, DEFAULT_IPADDR, DEFAULT_PORT, PROTO_TCP};

fn get_fgt_regex() -> &'static Regex {
    static LOG_REGEX: OnceLock<Regex> = OnceLock::new();

    LOG_REGEX.get_or_init(|| {
        Regex::new(r#"date=(?<date>\d{4}-\d{2}-\d{2}) time=(?<time>\d{2}:\d{2}:\d{2}).*?tz="(?<tz>\+\d{4})".*? srcip=(?<srcIp>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*dstip=(?<dstIp>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*proto=(?<proto>\d+).*srcport=(?<srcPort>\d+) dstport=(?<dstPort>\d+)"#)
            .expect("regex")
    })
}

fn parse_fgt_timestamp(date: &str, time: &str, tz: &str) -> Result<DateTime<FixedOffset>> {
    DateTime::parse_from_str(&format!("{date} {time} {tz}"), "%Y-%m-%d %H:%M:%S %z")
        .map_err(|e| anyhow!("{:?}", e))
}

impl ParseSecurityLog for Fgt {
    fn parse_security_log(
        line: &str,
        serial: i64,
        info: SecurityLogInfo,
    ) -> Result<(SecuLog, i64)> {
        let caps = get_fgt_regex().captures(line).context("invalid log line")?;

        let date = match caps.name("date") {
            Some(d) => d.as_str(),
            None => bail!("invalid date"),
        };
        let time = match caps.name("time") {
            Some(d) => d.as_str(),
            None => bail!("invalid time"),
        };
        let tz = match caps.name("tz") {
            Some(d) => d.as_str(),
            None => bail!("invalid tz"),
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

        let timestamp = parse_fgt_timestamp(date, time, tz)?
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
                proto: Some(proto),
                contents: line.to_string(),
            },
            timestamp,
        ))
    }
}
