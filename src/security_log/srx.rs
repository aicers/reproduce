use std::{net::IpAddr, str::FromStr, sync::OnceLock};

use anyhow::{Context, Result, anyhow, bail};
use chrono::DateTime;
use giganto_client::ingest::log::SecuLog;
use regex::Regex;

use super::{DEFAULT_IPADDR, DEFAULT_PORT, ParseSecurityLog, SecurityLogInfo, Srx, proto_to_u8};

fn get_srx_regex() -> &'static Regex {
    static LOG_REGEX: OnceLock<Regex> = OnceLock::new();

    LOG_REGEX.get_or_init(|| {
        Regex::new(r#"(?P<datetime>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3}\+\d{2}:\d{2}).*?source-address="(?P<srcIp>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})" source-port="(?P<srcPort>\d+)" destination-address="(?P<dstIp>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})" destination-port="(?P<dstPort>\d+)" protocol-name="(?P<proto>\w+)""#)
            .expect("regex")
    })
}

fn parse_srx_timestamp_ns(datetime: &str) -> Result<i64> {
    DateTime::parse_from_str(datetime, "%Y-%m-%dT%H:%M:%S%.f%z")
        .map_err(|e| anyhow!("{e:?}"))?
        .timestamp_nanos_opt()
        .context("to_timestamp_nanos")
}

impl ParseSecurityLog for Srx {
    fn parse_security_log(
        line: &str,
        serial: i64,
        info: SecurityLogInfo,
    ) -> Result<(SecuLog, i64)> {
        let caps = get_srx_regex().captures(line).context("invalid log line")?;

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

        let timestamp = parse_srx_timestamp_ns(datetime)? + serial;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_srx_timestamp_ns_returns_expected_nanos() {
        let ns = parse_srx_timestamp_ns("2024-01-02T03:04:05.123+09:00").unwrap();
        assert_eq!(ns, 1_704_132_245_123_000_000);
    }
}
