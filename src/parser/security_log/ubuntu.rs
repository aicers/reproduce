use std::sync::OnceLock;

use anyhow::{Context, Result, anyhow, bail};
use giganto_client::ingest::log::SecuLog;
use jiff::{Timestamp, tz::TimeZone};
use regex::Regex;

use super::{ParseSecurityLog, SecurityLogInfo, Ubuntu};

fn get_ubuntu_regex() -> &'static Regex {
    static LOG_REGEX: OnceLock<Regex> = OnceLock::new();

    LOG_REGEX
        .get_or_init(|| Regex::new(r"(?<datetime>\w{3} \d{1,2} \d{2}:\d{2}:\d{2})").expect("regex"))
}

fn parse_ubuntu_timestamp_ns(datetime: &str) -> Result<i64> {
    let year = Timestamp::now().to_zoned(TimeZone::UTC).year();
    let datetime_with_year = format!("{year} {datetime} +0900");
    Timestamp::strptime("%Y %b %d %H:%M:%S %z", datetime_with_year)
        .map_err(|e| anyhow!("{e:?}"))?
        .as_nanosecond()
        .try_into()
        .map_err(|e| anyhow!("{e:?}"))
}

impl ParseSecurityLog for Ubuntu {
    fn parse_security_log(
        line: &str,
        serial: i64,
        info: SecurityLogInfo,
    ) -> Result<(SecuLog, i64)> {
        let caps = get_ubuntu_regex()
            .captures(line)
            .context("invalid log line")?;

        let datetime = match caps.name("datetime") {
            Some(d) => d.as_str(),
            None => bail!("invalid datetime"),
        };

        let timestamp = parse_ubuntu_timestamp_ns(datetime)? + serial;

        Ok((
            SecuLog {
                kind: info.kind,
                log_type: info.log_type,
                version: info.version,
                orig_addr: None,
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
    use chrono::{Datelike, FixedOffset, TimeZone, Utc};

    use super::*;

    #[test]
    fn parse_ubuntu_rejects_invalid_format() {
        let info = SecurityLogInfo {
            kind: "ubuntu".to_string(),
            log_type: "syslog".to_string(),
            version: "20.04".to_string(),
        };

        // Empty string should fail
        assert!(Ubuntu::parse_security_log("", 0, info.clone()).is_err());

        // Random garbage (no valid datetime pattern) should fail
        assert!(Ubuntu::parse_security_log("12345 random garbage", 0, info.clone()).is_err());

        // Invalid month should fail
        assert!(
            Ubuntu::parse_security_log("Foo 12 00:00:04 safe-web-red systemd[1]: test", 0, info)
                .is_err()
        );
    }

    #[test]
    fn parse_ubuntu_maps_fields_correctly() {
        let info = SecurityLogInfo {
            kind: "ubuntu".to_string(),
            log_type: "syslog".to_string(),
            version: "20.04".to_string(),
        };

        let log = r"Oct 12 00:00:04 safe-web-red systemd[1]: logrotate.service: Succeeded.";

        let serial: i64 = 42;
        let (seculog, timestamp) = Ubuntu::parse_security_log(log, serial, info).unwrap();

        // Verify kind, log_type, version from info
        assert_eq!(seculog.kind, "ubuntu");
        assert_eq!(seculog.log_type, "syslog");
        assert_eq!(seculog.version, "20.04");

        // Ubuntu doesn't extract IP addresses, ports, or protocol
        assert_eq!(seculog.orig_addr, None);
        assert_eq!(seculog.orig_port, None);
        assert_eq!(seculog.resp_addr, None);
        assert_eq!(seculog.resp_port, None);
        assert_eq!(seculog.proto, None);

        // Note: timestamp validation uses current year, so we verify it's positive
        assert!(timestamp > 0);

        // Verify contents matches input
        assert_eq!(seculog.contents, log);
    }

    #[test]
    fn parse_ubuntu_timestamp_ns_returns_expected_nanos() {
        let ns = parse_ubuntu_timestamp_ns("Jan 02 03:04:05").unwrap();
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
    fn test_parse_ubuntu_timestamp_midnight() {
        let ns = parse_ubuntu_timestamp_ns("Jan 01 00:00:00").unwrap();
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
    fn test_parse_ubuntu_timestamp_end_of_day() {
        let ns = parse_ubuntu_timestamp_ns("Dec 31 23:59:59").unwrap();
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
    fn test_parse_ubuntu_timestamp_invalid_date() {
        assert!(parse_ubuntu_timestamp_ns("Feb 30 12:00:00").is_err());
    }

    #[test]
    fn test_parse_ubuntu_timestamp_invalid_month() {
        assert!(parse_ubuntu_timestamp_ns("Jnn 01 12:00:00").is_err());
    }

    #[test]
    fn test_parse_ubuntu_timestamp_invalid_hour() {
        assert!(parse_ubuntu_timestamp_ns("Jan 01 24:00:00").is_err());
    }

    #[test]
    fn test_parse_ubuntu_timestamp_invalid_format() {
        assert!(parse_ubuntu_timestamp_ns("Jan-01 12:00:00").is_err());
    }

    #[test]
    fn test_parse_ubuntu_timestamp_empty() {
        assert!(parse_ubuntu_timestamp_ns("").is_err());
    }
}
