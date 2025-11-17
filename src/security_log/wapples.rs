use std::{net::IpAddr, str::FromStr, sync::OnceLock};

use anyhow::{Context, Result, anyhow, bail};
use chrono::DateTime;
use giganto_client::ingest::log::SecuLog;
use regex::Regex;

use super::{DEFAULT_IPADDR, DEFAULT_PORT, PROTO_TCP, ParseSecurityLog, SecurityLogInfo, Wapples};

fn get_wapples_regex() -> &'static Regex {
    static LOG_REGEX: OnceLock<Regex> = OnceLock::new();

    LOG_REGEX.get_or_init(|| {
        Regex::new(r"\[?WAPPLES\]? DETECTION TIME : (?P<datetime>\S+ \S+ \S+) \[?WAPPLES\]? RULE NAME : [\w\s]+ \[?WAPPLES\]? \(client (?P<srcIp>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) \[?WAPPLES\]?\) -> \(server (?P<dstIp>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(?P<dstPort>\d+)\)")
            .expect("regex")
    })
}

fn parse_wapples_timestamp_ns(datetime: &str) -> Result<i64> {
    DateTime::parse_from_str(datetime, "%Y-%m-%d %H:%M:%S %z")
        .map_err(|e| anyhow!("{e:?}"))?
        .timestamp_nanos_opt()
        .context("to_timestamp_nanos")
}

impl ParseSecurityLog for Wapples {
    fn parse_security_log(
        line: &str,
        serial: i64,
        info: SecurityLogInfo,
    ) -> Result<(SecuLog, i64)> {
        let caps = get_wapples_regex()
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

        let resp_addr = match caps.name("dstIp") {
            Some(d) => IpAddr::from_str(d.as_str()).unwrap_or(DEFAULT_IPADDR),
            None => DEFAULT_IPADDR,
        };

        let resp_port = match caps.name("dstPort") {
            Some(d) => d.as_str().parse::<u16>().unwrap_or_default(),
            None => DEFAULT_PORT,
        };

        let timestamp = parse_wapples_timestamp_ns(datetime)? + serial;

        Ok((
            SecuLog {
                kind: info.kind,
                log_type: info.log_type,
                version: info.version,
                orig_addr: Some(orig_addr),
                orig_port: Some(DEFAULT_PORT),
                resp_addr: Some(resp_addr),
                resp_port: Some(resp_port),
                proto: Some(PROTO_TCP),
                contents: line.to_string(),
            },
            timestamp,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_wapples_timestamp_ns_returns_expected_nanos() {
        let ns = parse_wapples_timestamp_ns("2024-01-02 03:04:05 +0900").unwrap();
        assert_eq!(ns, 1_704_132_245_000_000_000);
    }
}
