use std::{net::IpAddr, str::FromStr, sync::OnceLock};

use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, Utc};
use giganto_client::ingest::log::SecuLog;
use regex::Regex;

use super::{
    DEFAULT_IPADDR, DEFAULT_PORT, PROTO_TCP, ParseSecurityLog, SecurityLogInfo, Wapples,
    datetime_to_nanos,
};

fn get_wapples_regex() -> &'static Regex {
    static LOG_REGEX: OnceLock<Regex> = OnceLock::new();

    LOG_REGEX.get_or_init(|| {
        Regex::new(r"\[?WAPPLES\]? DETECTION TIME : (?P<datetime>\S+ \S+ \S+) \[?WAPPLES\]? RULE NAME : [\w\s]+ \[?WAPPLES\]? \(client (?P<srcIp>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) \[?WAPPLES\]?\) -> \(server (?P<dstIp>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(?P<dstPort>\d+)\)")
            .expect("regex")
    })
}

fn parse_wapples_timestamp(datetime: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_str(datetime, "%Y-%m-%d %H:%M:%S %z")
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| anyhow!("{e:?}"))
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

        let timestamp = datetime_to_nanos(parse_wapples_timestamp(datetime)?)? + serial;

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
    use chrono::{DateTime, Utc};

    use super::parse_wapples_timestamp;

    #[test]
    fn wapples_timestamp_parses_inline_offset() {
        let ts = parse_wapples_timestamp("2020-01-09 09:26:09 +0900").unwrap();
        let expected =
            DateTime::parse_from_str("2020-01-09 09:26:09 +0900", "%Y-%m-%d %H:%M:%S %z")
                .expect("valid timestamp")
                .with_timezone(&Utc);
        assert_eq!(ts, expected);
    }

    #[test]
    fn wapples_timestamp_rejects_invalid_input() {
        assert!(parse_wapples_timestamp("2020-01-09 09:26:09").is_err());
    }
}
