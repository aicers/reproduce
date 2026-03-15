use std::{net::IpAddr, str::FromStr, sync::OnceLock};

use anyhow::{Context, Result, anyhow, bail};
use giganto_client::ingest::log::SecuLog;
use jiff::Timestamp;
use regex::Regex;

use super::{DEFAULT_IPADDR, Nginx, ParseSecurityLog, SecurityLogInfo};

fn get_nginx_regex() -> &'static Regex {
    static LOG_REGEX: OnceLock<Regex> = OnceLock::new();

    LOG_REGEX.get_or_init(|| {
        Regex::new(r"(?<srcIp>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?(?<datetime>\d{1,2}\/\w{3}\/\d{4}:\d{2}:\d{2}:\d{2} \+\d{4})")
            .expect("regex")
    })
}

fn parse_nginx_timestamp_ns(datetime: &str) -> Result<i64> {
    Timestamp::strptime("%d/%b/%Y:%T %z", datetime)
        .map_err(|e| anyhow!("{e:?}"))?
        .as_nanosecond()
        .try_into()
        .map_err(|e| anyhow!("{e:?}"))
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

        let timestamp = parse_nginx_timestamp_ns(datetime)? + serial;

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

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn parse_nginx_rejects_invalid_format() {
        let info = SecurityLogInfo {
            kind: "nginx".to_string(),
            log_type: "accesslog".to_string(),
            version: "1.25.2".to_string(),
        };

        // Empty string should fail
        assert!(Nginx::parse_security_log("", 0, info.clone()).is_err());

        // Random garbage should fail
        assert!(Nginx::parse_security_log("random garbage", 0, info.clone()).is_err());

        // Truncated log missing datetime should fail
        let truncated = r#"172.30.1.150 - - "GET /favicon.ico HTTP/1.1""#;
        assert!(Nginx::parse_security_log(truncated, 0, info).is_err());
    }

    #[test]
    fn parse_nginx_maps_fields_correctly() {
        let info = SecurityLogInfo {
            kind: "nginx".to_string(),
            log_type: "accesslog".to_string(),
            version: "1.25.2".to_string(),
        };

        let log = r#"172.30.1.150 - - [28/Jul/2023:00:00:24 +0900] "GET /favicon.ico HTTP/1.1" 404 1427 "http://www.moneta.co.kr/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36 Edg/115.0.1901.183""#;

        let serial: i64 = 42;
        let (seculog, timestamp) = Nginx::parse_security_log(log, serial, info).unwrap();

        // Verify kind, log_type, version from info
        assert_eq!(seculog.kind, "nginx");
        assert_eq!(seculog.log_type, "accesslog");
        assert_eq!(seculog.version, "1.25.2");

        // Verify parsed IP address (nginx only extracts source IP)
        assert_eq!(
            seculog.orig_addr,
            Some(IpAddr::V4(Ipv4Addr::new(172, 30, 1, 150)))
        );

        // Nginx doesn't extract ports or destination
        assert_eq!(seculog.orig_port, None);
        assert_eq!(seculog.resp_addr, None);
        assert_eq!(seculog.resp_port, None);
        assert_eq!(seculog.proto, None);

        // Verify timestamp matches expected value (datetime + serial offset)
        // "28/Jul/2023:00:00:24 +0900" = 2023-07-27 15:00:24 UTC = 1690470024 seconds since epoch
        assert_eq!(timestamp, 1_690_470_024_000_000_000 + serial);

        // Verify contents matches input
        assert_eq!(seculog.contents, log);
    }

    #[test]
    fn parse_nginx_timestamp_ns_returns_expected_nanos() {
        let ns = parse_nginx_timestamp_ns("02/Jan/2024:03:04:05 +0900").unwrap();
        assert_eq!(ns, 1_704_132_245_000_000_000);
    }

    #[test]
    fn test_parse_nginx_timestamp_midnight() {
        let ns = parse_nginx_timestamp_ns("01/Jan/2024:00:00:00 +0900").unwrap();
        assert_eq!(ns, 1_704_034_800_000_000_000); // 2024-01-01 00:00:00 +0900 -> 2023-12-31 15:00:00 UTC
    }

    #[test]
    fn test_parse_nginx_timestamp_end_of_day() {
        let ns = parse_nginx_timestamp_ns("31/Dec/2023:23:59:59 +0900").unwrap();
        assert_eq!(ns, 1_704_034_799_000_000_000); // 2023-12-31 23:59:59 +0900 -> 2023-12-31 14:59:59 UTC
    }

    #[test]
    fn test_parse_nginx_timestamp_leap_day() {
        let ns = parse_nginx_timestamp_ns("29/Feb/2024:12:00:00 +0900").unwrap();
        assert_eq!(ns, 1_709_175_600_000_000_000); // 03:00:00 UTC
    }

    #[test]
    fn test_parse_nginx_timestamp_invalid_date() {
        assert!(parse_nginx_timestamp_ns("30/Feb/2023:12:00:00 +0900").is_err());
    }

    #[test]
    fn test_parse_nginx_timestamp_invalid_month() {
        assert!(parse_nginx_timestamp_ns("15/Decem/2023:12:00:00 +0900").is_err());
    }

    #[test]
    fn test_parse_nginx_timestamp_invalid_hour() {
        assert!(parse_nginx_timestamp_ns("15/Jan/2023:24:00:00 +0900").is_err());
    }

    #[test]
    fn test_parse_nginx_timestamp_invalid_format() {
        assert!(parse_nginx_timestamp_ns("2023-01-15 12:00:00 +0900").is_err());
    }

    #[test]
    fn test_parse_nginx_timestamp_empty() {
        assert!(parse_nginx_timestamp_ns("").is_err());
    }
}
