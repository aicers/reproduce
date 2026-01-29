use std::{net::IpAddr, str::FromStr, sync::OnceLock};

use anyhow::{Context, Result, anyhow, bail};
use giganto_client::ingest::log::SecuLog;
use jiff::Timestamp;
use regex::Regex;

use super::{DEFAULT_IPADDR, DEFAULT_PORT, Mf2, ParseSecurityLog, SecurityLogInfo, proto_to_u8};

fn get_mf2_regex() -> &'static Regex {
    static LOG_REGEX: OnceLock<Regex> = OnceLock::new();

    LOG_REGEX.get_or_init(|| {
        Regex::new(r"\](?P<datetime>\d{4}\-\d{1,2}\-\d{1,2} \d{2}:\d{2}:\d{2}),.*?,(?P<srcIp>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),(?P<srcPort>\d+),(?P<dstIp>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),(?P<dstPort>\d+),(?P<proto>\w+),")
            .expect("regex")
    })
}

fn parse_mf2_timestamp_ns(datetime: &str) -> Result<i64> {
    Timestamp::strptime("%Y-%m-%d %H:%M:%S %z", format!("{datetime} +0900"))
        .map_err(|e| anyhow!("{e:?}"))?
        .as_nanosecond()
        .try_into()
        .map_err(|e| anyhow!("{e:?}"))
}

impl ParseSecurityLog for Mf2 {
    fn parse_security_log(
        line: &str,
        serial: i64,
        info: SecurityLogInfo,
    ) -> Result<(SecuLog, i64)> {
        let caps = get_mf2_regex().captures(line).context("invalid log line")?;

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

        let timestamp = parse_mf2_timestamp_ns(datetime)? + serial;

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
    use std::net::Ipv4Addr;

    use super::*;
    use crate::security_log::PROTO_TCP;

    #[test]
    fn parse_mf2_rejects_invalid_format() {
        let info = SecurityLogInfo {
            kind: "mf2".to_string(),
            log_type: "ips".to_string(),
            version: "4.0".to_string(),
        };

        // Empty string should fail
        assert!(Mf2::parse_security_log("", 0, info.clone()).is_err());

        // Random garbage should fail
        assert!(Mf2::parse_security_log("random garbage", 0, info.clone()).is_err());

        // Truncated log missing IP/port fields should fail
        // The regex requires: ]datetime,...,srcIp,srcPort,dstIp,dstPort,proto,
        let truncated = "<190>1 2020-07-13T00:33:28.957810Z [ips_ddos_detect] \
            [211.217.5.120]2020-07-13 09:33:23,KOFIH,#21965,192.168.20.79";
        assert!(Mf2::parse_security_log(truncated, 0, info).is_err());
    }

    #[test]
    fn parse_mf2_maps_fields_correctly() {
        let info = SecurityLogInfo {
            kind: "mf2".to_string(),
            log_type: "ips".to_string(),
            version: "4.0".to_string(),
        };

        let log = "<190>1 2020-07-13T00:33:28.957810Z [ips_ddos_detect] \
            [211.217.5.120]2020-07-13 09:33:23,KOFIH,\
            #21965(HTTP Sensitive file Access Attempt(index.jsp)),#0(IPS),\
            192.168.20.79,56889,211.42.85.240,80,TCP,don't frag/last frag,\
            AP,24:f5:aa:e1:fc:a0,1,541,detect,0";

        let (seculog, timestamp) = Mf2::parse_security_log(log, 0, info).unwrap();

        // Verify kind, log_type, version from info
        assert_eq!(seculog.kind, "mf2");
        assert_eq!(seculog.log_type, "ips");
        assert_eq!(seculog.version, "4.0");

        // Verify parsed IP addresses
        assert_eq!(
            seculog.orig_addr,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 20, 79)))
        );
        assert_eq!(
            seculog.resp_addr,
            Some(IpAddr::V4(Ipv4Addr::new(211, 42, 85, 240)))
        );

        // Verify ports
        assert_eq!(seculog.orig_port, Some(56889));
        assert_eq!(seculog.resp_port, Some(80));

        // Verify protocol is TCP
        assert_eq!(seculog.proto, Some(PROTO_TCP));

        // Verify timestamp is positive
        assert!(timestamp > 0);

        // Verify contents matches input
        assert_eq!(seculog.contents, log);
    }

    #[test]
    fn parse_mf2_timestamp_ns_returns_expected_nanos() {
        let ns = parse_mf2_timestamp_ns("2024-01-02 03:04:05").unwrap();
        assert_eq!(ns, 1_704_132_245_000_000_000);
    }

    #[test]
    fn test_parse_mf2_timestamp_midnight() {
        let ns = parse_mf2_timestamp_ns("2024-01-01 00:00:00").unwrap();
        assert_eq!(ns, 1_704_034_800_000_000_000); // 2023-12-31 15:00:00 UTC
    }

    #[test]
    fn test_parse_mf2_timestamp_end_of_day() {
        let ns = parse_mf2_timestamp_ns("2023-12-31 23:59:59").unwrap();
        assert_eq!(ns, 1_704_034_799_000_000_000); // 14:59:59 UTC
    }

    #[test]
    fn test_parse_mf2_timestamp_leap_day() {
        let ns = parse_mf2_timestamp_ns("2024-02-29 12:00:00").unwrap();
        assert_eq!(ns, 1_709_175_600_000_000_000); // 03:00:00 UTC
    }

    #[test]
    fn test_parse_mf2_timestamp_invalid_date() {
        assert!(parse_mf2_timestamp_ns("2023-02-30 12:00:00").is_err());
    }

    #[test]
    fn test_parse_mf2_timestamp_invalid_month() {
        assert!(parse_mf2_timestamp_ns("2023-13-15 12:00:00").is_err());
    }

    #[test]
    fn test_parse_mf2_timestamp_invalid_hour() {
        assert!(parse_mf2_timestamp_ns("2023-01-15 24:00:00").is_err());
    }

    #[test]
    fn test_parse_mf2_timestamp_invalid_format() {
        assert!(parse_mf2_timestamp_ns("2023/01/15 12:00:00").is_err());
    }

    #[test]
    fn test_parse_mf2_timestamp_empty() {
        assert!(parse_mf2_timestamp_ns("").is_err());
    }
}
