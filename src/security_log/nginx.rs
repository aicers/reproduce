use std::{net::IpAddr, str::FromStr, sync::OnceLock};

use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, FixedOffset};
use giganto_client::ingest::log::SecuLog;
use regex::Regex;

use super::{Nginx, ParseSecurityLog, SecurityLogInfo, DEFAULT_IPADDR};

fn get_nginx_regex() -> &'static Regex {
    static LOG_REGEX: OnceLock<Regex> = OnceLock::new();

    LOG_REGEX.get_or_init(|| {
        Regex::new(r"(?<srcIp>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?(?<datetime>\d{1,2}\/\w{3}\/\d{4}:\d{2}:\d{2}:\d{2} \+\d{4})")
            .expect("regex")
    })
}

fn parse_nginx_timestamp(datetime: &str) -> Result<DateTime<FixedOffset>> {
    DateTime::parse_from_str(datetime, "%d/%b/%Y:%T %z").map_err(|e| anyhow!("{e:?}"))
}

impl ParseSecurityLog for Nginx {
    fn parse_security_log(
        line: &str,
        serial: i64,
        info: SecurityLogInfo,
    ) -> Result<(SecuLog, i64)> {
        let caps = get_nginx_regex()
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

        let timestamp = parse_nginx_timestamp(datetime)?
            .timestamp_nanos_opt()
            .context("to_timestamp_nanos")?
            + serial;

        Ok((
            SecuLog {
                kind: info.kind,
                log_type: info.log_type,
                version: info.version,
                orig_addr: Some(orig_addr),
                orig_port: None,
                resp_addr: None,
                resp_port: None,
                proto: None,
                contents: line.to_string(),
            },
            timestamp,
        ))
    }
}
