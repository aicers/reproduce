use std::{net::IpAddr, str::FromStr, sync::OnceLock};

use anyhow::{Context, Result, anyhow, bail};
use giganto_client::ingest::log::SecuLog;
use jiff::Timestamp;
use regex::Regex;

use super::{DEFAULT_IPADDR, DEFAULT_PORT, PROTO_TCP, ParseSecurityLog, SecurityLogInfo, Tg};

fn get_tg_regex() -> &'static Regex {
    static LOG_REGEX: OnceLock<Regex> = OnceLock::new();

    LOG_REGEX.get_or_init(|| {
        Regex::new(r"`(?P<datetime>\d{8}`\d{2}:\d{2}:\d{2})`.*?`(?P<proto>\d+)`(?P<srcIp>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`(?P<srcPort>\d+)`(?P<dstIp>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`(?P<dstPort>\d+)`")
            .expect("regex")
    })
}

fn parse_tg_timestamp_ns(datetime: &str) -> Result<i64> {
    Timestamp::strptime("%Y%m%d`%H:%M:%S %z", format!("{datetime} +0900"))
        .map_err(|e| anyhow!("{e:?}"))?
        .as_nanosecond()
        .try_into()
        .map_err(|e| anyhow!("{e:?}"))
}

impl ParseSecurityLog for Tg {
    fn parse_security_log(
        line: &str,
        serial: i64,
        info: SecurityLogInfo,
    ) -> Result<(SecuLog, i64)> {
        let caps = get_tg_regex().captures(line).context("invalid log line")?;

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

        let timestamp = parse_tg_timestamp_ns(datetime)? + serial;

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
    use super::*;

    #[test]
    fn parse_tg_timestamp_ns_returns_expected_nanos() {
        let ns = parse_tg_timestamp_ns("20240102`03:04:05").unwrap();
        assert_eq!(ns, 1_704_132_245_000_000_000);
    }

    #[test]
    fn test_parse_tg_timestamp_midnight() {
        let ns = parse_tg_timestamp_ns("20240101`00:00:00").unwrap();
        assert_eq!(ns, 1_704_034_800_000_000_000); // 2023-12-31 15:00:00 UTC
    }

    #[test]
    fn test_parse_tg_timestamp_end_of_day() {
        let ns = parse_tg_timestamp_ns("20231231`23:59:59").unwrap();
        assert_eq!(ns, 1_704_034_799_000_000_000); // 14:59:59 UTC
    }

    #[test]
    fn test_parse_tg_timestamp_leap_day() {
        let ns = parse_tg_timestamp_ns("20240229`12:00:00").unwrap();
        assert_eq!(ns, 1_709_175_600_000_000_000); // 03:00:00 UTC
    }

    #[test]
    fn test_parse_tg_timestamp_invalid_date() {
        assert!(parse_tg_timestamp_ns("20230230`12:00:00").is_err());
    }

    #[test]
    fn test_parse_tg_timestamp_invalid_month() {
        assert!(parse_tg_timestamp_ns("20231315`12:00:00").is_err());
    }

    #[test]
    fn test_parse_tg_timestamp_invalid_hour() {
        assert!(parse_tg_timestamp_ns("20230115`24:00:00").is_err());
    }

    #[test]
    fn test_parse_tg_timestamp_invalid_format() {
        assert!(parse_tg_timestamp_ns("2023-01-15`12:00:00").is_err());
    }

    #[test]
    fn test_parse_tg_timestamp_empty() {
        assert!(parse_tg_timestamp_ns("").is_err());
    }
}
