use std::{net::IpAddr, str::FromStr, sync::OnceLock};

use anyhow::{Context, Result, anyhow, bail};
use giganto_client::ingest::log::SecuLog;
use jiff::tz::{Offset, TimeZone};
use regex::Regex;

use super::{DEFAULT_IPADDR, Nginx, ParseSecurityLog, SecurityLogInfo};

fn get_nginx_regex() -> &'static Regex {
    static LOG_REGEX: OnceLock<Regex> = OnceLock::new();

    LOG_REGEX.get_or_init(|| {
        Regex::new(r"(?<srcIp>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?(?<datetime>\d{1,2}\/\w{3}\/\d{4}:\d{2}:\d{2}:\d{2}) (?<offset>\+\d{4})")
            .expect("regex")
    })
}

fn parse_nginx_timestamp_ns(datetime: &str, offset_str: &str) -> Result<i64> {
    // Parse the offset string like "+0900" to get hours and minutes
    let offset_hours: i8 = offset_str[1..3]
        .parse()
        .map_err(|_| anyhow!("invalid offset hours"))?;
    let offset_mins: i8 = offset_str[3..5]
        .parse()
        .map_err(|_| anyhow!("invalid offset minutes"))?;
    let sign: i32 = if offset_str.starts_with('-') { -1 } else { 1 };
    let offset =
        Offset::from_seconds(sign * (i32::from(offset_hours) * 3600 + i32::from(offset_mins) * 60))
            .map_err(|e| anyhow!("invalid offset: {e}"))?;

    let civil_dt = jiff::civil::DateTime::strptime("%d/%b/%Y:%H:%M:%S", datetime)
        .map_err(|e| anyhow!("parse error: {e}"))?;
    let tz = TimeZone::fixed(offset);
    let zoned = civil_dt
        .to_zoned(tz)
        .map_err(|e| anyhow!("zoned conversion error: {e}"))?;
    i64::try_from(zoned.timestamp().as_nanosecond()).context("timestamp nanoseconds overflow")
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

        let offset = match caps.name("offset") {
            Some(o) => o.as_str(),
            None => bail!("invalid offset"),
        };

        let orig_addr = match caps.name("srcIp") {
            Some(d) => IpAddr::from_str(d.as_str()).unwrap_or(DEFAULT_IPADDR),
            None => DEFAULT_IPADDR,
        };

        let timestamp = parse_nginx_timestamp_ns(datetime, offset)? + serial;

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
    use super::*;

    #[test]
    fn parse_nginx_timestamp_ns_returns_expected_nanos() {
        let ns = parse_nginx_timestamp_ns("02/Jan/2024:03:04:05", "+0900").unwrap();
        assert_eq!(ns, 1_704_132_245_000_000_000);
    }

    #[test]
    fn test_parse_nginx_timestamp_midnight() {
        let ns = parse_nginx_timestamp_ns("01/Jan/2024:00:00:00", "+0900").unwrap();
        assert_eq!(ns, 1_704_034_800_000_000_000); // 2024-01-01 00:00:00 +0900 -> 2023-12-31 15:00:00 UTC
    }

    #[test]
    fn test_parse_nginx_timestamp_end_of_day() {
        let ns = parse_nginx_timestamp_ns("31/Dec/2023:23:59:59", "+0900").unwrap();
        assert_eq!(ns, 1_704_034_799_000_000_000); // 2023-12-31 23:59:59 +0900 -> 2023-12-31 14:59:59 UTC
    }

    #[test]
    fn test_parse_nginx_timestamp_leap_day() {
        let ns = parse_nginx_timestamp_ns("29/Feb/2024:12:00:00", "+0900").unwrap();
        assert_eq!(ns, 1_709_175_600_000_000_000); // 03:00:00 UTC
    }

    #[test]
    fn test_parse_nginx_timestamp_invalid_date() {
        assert!(parse_nginx_timestamp_ns("30/Feb/2023:12:00:00", "+0900").is_err());
    }

    #[test]
    fn test_parse_nginx_timestamp_invalid_month() {
        assert!(parse_nginx_timestamp_ns("15/Decem/2023:12:00:00", "+0900").is_err());
    }

    #[test]
    fn test_parse_nginx_timestamp_invalid_hour() {
        assert!(parse_nginx_timestamp_ns("15/Jan/2023:24:00:00", "+0900").is_err());
    }

    #[test]
    fn test_parse_nginx_timestamp_invalid_format() {
        assert!(parse_nginx_timestamp_ns("2023-01-15 12:00:00", "+0900").is_err());
    }

    #[test]
    fn test_parse_nginx_timestamp_empty() {
        assert!(parse_nginx_timestamp_ns("", "+0900").is_err());
    }
}
