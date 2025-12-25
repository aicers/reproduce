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

    #[test]
    fn test_parse_srx_timestamp_single_digit_subsecond() {
        let ns = parse_srx_timestamp_ns("2024-01-02T03:04:05.1+09:00").unwrap();
        assert_eq!(ns, 1_704_132_245_100_000_000);
    }

    #[test]
    fn test_parse_srx_timestamp_max_subseconds() {
        let ns = parse_srx_timestamp_ns("2024-01-02T03:04:05.999999999+09:00").unwrap();
        assert_eq!(ns, 1_704_132_245_999_999_999);
    }

    #[test]
    fn test_parse_srx_timestamp_midnight() {
        let ns = parse_srx_timestamp_ns("2024-01-01T00:00:00.000+09:00").unwrap();
        assert_eq!(ns, 1_704_034_800_000_000_000); // 2023-12-31 15:00:00 UTC
    }

    #[test]
    fn test_parse_srx_timestamp_end_of_day() {
        let ns = parse_srx_timestamp_ns("2023-12-31T23:59:59.999+09:00").unwrap();
        assert_eq!(ns, 1_704_034_799_999_000_000); // 14:59:59.999 UTC
    }

    #[test]
    fn test_parse_srx_timestamp_leap_day() {
        let ns = parse_srx_timestamp_ns("2024-02-29T12:00:00.000+09:00").unwrap();
        assert_eq!(ns, 1_709_175_600_000_000_000); // 03:00:00 UTC
    }

    #[test]
    fn test_parse_srx_timestamp_invalid_date() {
        assert!(parse_srx_timestamp_ns("2023-02-30T12:00:00.000+09:00").is_err());
    }

    #[test]
    fn test_parse_srx_timestamp_invalid_month() {
        assert!(parse_srx_timestamp_ns("2023-13-15T12:00:00.000+09:00").is_err());
    }

    #[test]
    fn test_parse_srx_timestamp_invalid_hour() {
        assert!(parse_srx_timestamp_ns("2023-01-15T24:00:00.000+09:00").is_err());
    }

    #[test]
    fn test_parse_srx_timestamp_invalid_format() {
        assert!(parse_srx_timestamp_ns("2023-01-15 12:00:00").is_err());
    }

    #[test]
    fn test_parse_srx_timestamp_empty() {
        assert!(parse_srx_timestamp_ns("").is_err());
    }
}
