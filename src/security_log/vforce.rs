use std::{net::IpAddr, str::FromStr, sync::OnceLock};

use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, Datelike, Utc};
use giganto_client::ingest::log::SecuLog;
use regex::Regex;

use super::{DEFAULT_IPADDR, DEFAULT_PORT, PROTO_TCP, ParseSecurityLog, SecurityLogInfo, Vforce};

fn get_vforce_regex() -> &'static Regex {
    static LOG_REGEX: OnceLock<Regex> = OnceLock::new();

    LOG_REGEX.get_or_init(|| {
        Regex::new(r">(?<datetime>\w{3} \d{1,2} \d{2}:\d{2}:\d{2}).*?Src:(?<srcIp>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}), Dst:(?<dstIp>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}), Proto:(?<proto>\d+), Spt_c:(?<srcPort>\d+), Dpt_t:(?<dstPort>\d+),")
            .expect("regex")
    })
}

fn parse_vforce_timestamp_ns(datetime: &str) -> Result<i64> {
    let now = Utc::now();
    DateTime::parse_from_str(
        &format!("{} {datetime} +0900", now.year()),
        "%Y %b %d %H:%M:%S %z",
    )
    .map_err(|e| anyhow!("{e:?}"))?
    .timestamp_nanos_opt()
    .context("to_timestamp_nanos")
}

impl ParseSecurityLog for Vforce {
    fn parse_security_log(
        line: &str,
        serial: i64,
        info: SecurityLogInfo,
    ) -> Result<(SecuLog, i64)> {
        let caps = get_vforce_regex()
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
            Some(d) => d.as_str().parse::<u8>().unwrap_or(PROTO_TCP),
            None => PROTO_TCP,
        };

        let timestamp = parse_vforce_timestamp_ns(datetime)? + serial;

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

#[cfg(test)]
mod tests {
    use chrono::{Datelike, FixedOffset, TimeZone, Utc};

    use super::*;

    #[test]
    fn parse_vforce_timestamp_ns_returns_expected_nanos() {
        let ns = parse_vforce_timestamp_ns("Jan 02 03:04:05").unwrap();
        let year = Utc::now().year();
        let expected = FixedOffset::east_opt(9 * 3600)
            .unwrap()
            .with_ymd_and_hms(year, 1, 2, 3, 4, 5)
            .unwrap()
            .timestamp_nanos_opt()
            .unwrap();
        assert_eq!(ns, expected);
    }

    #[test]
    fn test_parse_vforce_timestamp_midnight() {
        let ns = parse_vforce_timestamp_ns("Jan 01 00:00:00").unwrap();
        let year = Utc::now().year();
        let expected = FixedOffset::east_opt(9 * 3600)
            .unwrap()
            .with_ymd_and_hms(year, 1, 1, 0, 0, 0)
            .unwrap()
            .timestamp_nanos_opt()
            .unwrap();
        assert_eq!(ns, expected);
    }

    #[test]
    fn test_parse_vforce_timestamp_end_of_day() {
        let ns = parse_vforce_timestamp_ns("Dec 31 23:59:59").unwrap();
        let year = Utc::now().year();
        let expected = FixedOffset::east_opt(9 * 3600)
            .unwrap()
            .with_ymd_and_hms(year, 12, 31, 23, 59, 59)
            .unwrap()
            .timestamp_nanos_opt()
            .unwrap();
        assert_eq!(ns, expected);
    }

    #[test]
    fn test_parse_vforce_timestamp_invalid_date() {
        assert!(parse_vforce_timestamp_ns("Feb 30 12:00:00").is_err());
    }

    #[test]
    fn test_parse_vforce_timestamp_invalid_month() {
        assert!(parse_vforce_timestamp_ns("Jnn 01 12:00:00").is_err());
    }

    #[test]
    fn test_parse_vforce_timestamp_invalid_hour() {
        assert!(parse_vforce_timestamp_ns("Jan 01 24:00:00").is_err());
    }

    #[test]
    fn test_parse_vforce_timestamp_invalid_format() {
        assert!(parse_vforce_timestamp_ns("Jan-01 12:00:00").is_err());
    }

    #[test]
    fn test_parse_vforce_timestamp_empty() {
        assert!(parse_vforce_timestamp_ns("").is_err());
    }
}
