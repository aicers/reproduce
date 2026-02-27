use std::{net::IpAddr, str::FromStr, sync::OnceLock};

use anyhow::{Context, Result, anyhow, bail};
use giganto_client::ingest::log::SecuLog;
use jiff::Timestamp;
use regex::Regex;

use super::{Aiwaf, DEFAULT_IPADDR, DEFAULT_PORT, PROTO_TCP, ParseSecurityLog, SecurityLogInfo};

fn get_aiwaf_regex() -> &'static Regex {
    static LOG_REGEX: OnceLock<Regex> = OnceLock::new();

    LOG_REGEX.get_or_init(|| {
        Regex::new(r"(?<datetime>\d{4}-\d{1,2}-\d{1,2} \d{2}:\d{2}:\d{2})\|.*?\|(?<srcIp>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\|(?<srcPort>\d+)\|(?<dstIp>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\|(?<dstPort>\d+)")
            .expect("regex")
    })
}

fn parse_aiwaf_timestamp_ns(datetime: &str) -> Result<i64> {
    Timestamp::strptime("%Y-%m-%d %H:%M:%S %z", format!("{datetime} +0900"))
        .map_err(|e| anyhow!("{e:?}"))?
        .as_nanosecond()
        .try_into()
        .map_err(|e| anyhow!("{e:?}"))
}

impl ParseSecurityLog for Aiwaf {
    fn parse_security_log(
        line: &str,
        serial: i64,
        info: SecurityLogInfo,
    ) -> Result<(SecuLog, i64)> {
        let caps = get_aiwaf_regex()
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
            Some(d) => d.as_str().parse::<u16>().unwrap_or(DEFAULT_PORT),
            None => DEFAULT_PORT,
        };

        let resp_addr = match caps.name("dstIp") {
            Some(d) => IpAddr::from_str(d.as_str()).unwrap_or(DEFAULT_IPADDR),
            None => DEFAULT_IPADDR,
        };

        let resp_port = match caps.name("dstPort") {
            Some(d) => d.as_str().parse::<u16>().unwrap_or(DEFAULT_PORT),
            None => DEFAULT_PORT,
        };

        let timestamp = parse_aiwaf_timestamp_ns(datetime)? + serial;

        Ok((
            SecuLog {
                kind: info.kind,
                log_type: info.log_type,
                version: info.version,
                orig_addr: Some(orig_addr),
                orig_port: Some(orig_port),
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
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn parse_aiwaf_rejects_invalid_format() {
        let info = SecurityLogInfo {
            kind: "aiwaf".to_string(),
            log_type: "waf".to_string(),
            version: "4.1".to_string(),
        };

        // Empty string should fail
        assert!(Aiwaf::parse_security_log("", 0, info.clone()).is_err());

        // Random garbage should fail
        assert!(Aiwaf::parse_security_log("random garbage", 0, info.clone()).is_err());

        // Truncated log missing IP/port fields should fail
        let truncated = "DETECT|2019-07-19 11:47:15|1.1.1.2|v4.1|192.168.70.254|52677";
        assert!(Aiwaf::parse_security_log(truncated, 0, info).is_err());
    }

    #[test]
    fn parse_aiwaf_maps_fields_correctly() {
        let info = SecurityLogInfo {
            kind: "aiwaf".to_string(),
            log_type: "waf".to_string(),
            version: "4.1".to_string(),
        };

        let log = "DETECT|2019-07-19 11:47:15|1.1.1.2|v4.1|192.168.70.254|52677|192.168.200.44|80|Personal Information Leakage|중간|탐지|POST /ekp/rss.do";

        let serial: i64 = 42;
        let (seculog, timestamp) = Aiwaf::parse_security_log(log, serial, info).unwrap();

        // Verify kind, log_type, version from info
        assert_eq!(seculog.kind, "aiwaf");
        assert_eq!(seculog.log_type, "waf");
        assert_eq!(seculog.version, "4.1");

        // Verify parsed IP addresses
        assert_eq!(
            seculog.orig_addr,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 70, 254)))
        );
        assert_eq!(
            seculog.resp_addr,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 200, 44)))
        );

        // Verify ports
        assert_eq!(seculog.orig_port, Some(52677));
        assert_eq!(seculog.resp_port, Some(80));

        // Verify protocol is TCP
        assert_eq!(seculog.proto, Some(PROTO_TCP));

        // Verify timestamp matches expected value (datetime + serial offset)
        // "2019-07-19 11:47:15" +0900 = 2019-07-19 02:47:15 UTC = 1563504435 seconds since epoch
        assert_eq!(timestamp, 1_563_504_435_000_000_000 + serial);

        // Verify contents matches input
        assert_eq!(seculog.contents, log);
    }

    #[test]
    fn parse_aiwaf_timestamp_ns_returns_expected_nanos() {
        let ns = parse_aiwaf_timestamp_ns("2024-01-02 03:04:05").unwrap();
        assert_eq!(ns, 1_704_132_245_000_000_000);
    }

    #[test]
    fn test_parse_aiwaf_timestamp_midnight() {
        let ns = parse_aiwaf_timestamp_ns("2024-01-01 00:00:00").unwrap();
        assert_eq!(ns, 1_704_034_800_000_000_000); // 2023-12-31 15:00:00 UTC
    }

    #[test]
    fn test_parse_aiwaf_timestamp_end_of_day() {
        let ns = parse_aiwaf_timestamp_ns("2023-12-31 23:59:59").unwrap();
        assert_eq!(ns, 1_704_034_799_000_000_000); // 2023-12-31 14:59:59 UTC
    }

    #[test]
    fn test_parse_aiwaf_timestamp_leap_day() {
        let ns = parse_aiwaf_timestamp_ns("2024-02-29 12:00:00").unwrap();
        assert_eq!(ns, 1_709_175_600_000_000_000); // 03:00:00 UTC
    }

    #[test]
    fn test_parse_aiwaf_timestamp_invalid_date() {
        assert!(parse_aiwaf_timestamp_ns("2023-02-30 12:00:00").is_err());
    }

    #[test]
    fn test_parse_aiwaf_timestamp_invalid_month() {
        assert!(parse_aiwaf_timestamp_ns("2023-13-15 12:00:00").is_err());
    }

    #[test]
    fn test_parse_aiwaf_timestamp_invalid_hour() {
        assert!(parse_aiwaf_timestamp_ns("2023-01-15 24:00:00").is_err());
    }

    #[test]
    fn test_parse_aiwaf_timestamp_invalid_format() {
        assert!(parse_aiwaf_timestamp_ns("2023/01/15 12:00:00").is_err());
    }

    #[test]
    fn test_parse_aiwaf_timestamp_empty() {
        assert!(parse_aiwaf_timestamp_ns("").is_err());
    }
}
