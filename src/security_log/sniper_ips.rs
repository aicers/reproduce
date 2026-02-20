use std::{net::IpAddr, str::FromStr, sync::OnceLock};

use anyhow::{Context, Result, anyhow, bail};
use giganto_client::ingest::log::SecuLog;
use jiff::Timestamp;
use regex::Regex;

use super::{
    DEFAULT_IPADDR, DEFAULT_PORT, ParseSecurityLog, SecurityLogInfo, SniperIps, proto_to_u8,
};

fn get_sniper_regex() -> &'static Regex {
    static LOG_REGEX: OnceLock<Regex> = OnceLock::new();

    LOG_REGEX.get_or_init(|| {
        Regex::new(r"\[Time=(?P<datetime>\d{4}\/\d{1,2}\/\d{1,2} \d{2}\:\d{2}\:\d{2})\], \[Hacker=(?P<srcIp>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\], \[Victim=(?P<dstIp>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\], \[Protocol=(?P<proto>\w+)\/(?P<dstPort>\d+)\],.*\[SrcPort=(?P<srcPort>\d+)\]")
            .expect("regex")
    })
}

fn parse_sniper_timestamp_ns(datetime: &str) -> Result<i64> {
    Timestamp::strptime("%Y/%m/%d %H:%M:%S %z", format!("{datetime} +0900"))
        .map_err(|e| anyhow!("{e:?}"))?
        .as_nanosecond()
        .try_into()
        .map_err(|e| anyhow!("{e:?}"))
}

impl ParseSecurityLog for SniperIps {
    fn parse_security_log(
        line: &str,
        serial: i64,
        info: SecurityLogInfo,
    ) -> Result<(SecuLog, i64)> {
        let caps = get_sniper_regex()
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

        let proto = match caps.name("proto") {
            Some(d) => d.as_str(),
            None => "TCP",
        };

        let timestamp = parse_sniper_timestamp_ns(datetime)? + serial;

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
    use crate::security_log::PROTO_UDP;

    #[test]
    fn parse_sniper_rejects_invalid_format() {
        let info = SecurityLogInfo {
            kind: "sniper".to_string(),
            log_type: "ips".to_string(),
            version: "8.0".to_string(),
        };

        // Empty string should fail
        assert!(SniperIps::parse_security_log("", 0, info.clone()).is_err());

        // Random garbage should fail
        assert!(SniperIps::parse_security_log("random garbage", 0, info.clone()).is_err());

        // Truncated log missing required fields should fail
        let truncated = "<36>[SNIPER-0123] [Attack_Name=(0395)UDP Source-IP Flooding], [Time=2020/07/13 09:45:54]";
        assert!(SniperIps::parse_security_log(truncated, 0, info).is_err());
    }

    #[test]
    fn parse_sniper_maps_fields_correctly() {
        let info = SecurityLogInfo {
            kind: "sniper".to_string(),
            log_type: "ips".to_string(),
            version: "8.0".to_string(),
        };

        let log = "<36>[SNIPER-0123] [Attack_Name=(0395)UDP Source-IP Flooding], [Time=2020/07/13 09:45:54], [Hacker=168.126.63.1], [Victim=192.168.253.13], [Protocol=udp/56157], [Risk=Low], [Handling=Alarm], [Information=], [SrcPort=53], [HackType=00001]";

        let serial: i64 = 42;
        let (seculog, timestamp) = SniperIps::parse_security_log(log, serial, info).unwrap();

        // Verify kind, log_type, version from info
        assert_eq!(seculog.kind, "sniper");
        assert_eq!(seculog.log_type, "ips");
        assert_eq!(seculog.version, "8.0");

        // Verify parsed IP addresses
        assert_eq!(
            seculog.orig_addr,
            Some(IpAddr::V4(Ipv4Addr::new(168, 126, 63, 1)))
        );
        assert_eq!(
            seculog.resp_addr,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 253, 13)))
        );

        // Verify ports
        assert_eq!(seculog.orig_port, Some(53));
        assert_eq!(seculog.resp_port, Some(56157));

        // Verify protocol is UDP
        assert_eq!(seculog.proto, Some(PROTO_UDP));

        // Verify timestamp matches expected value (datetime + serial offset)
        // "2020/07/13 09:45:54" +0900 = 2020-07-13 00:45:54 UTC = 1594601154 seconds since epoch
        assert_eq!(timestamp, 1_594_601_154_000_000_000 + serial);

        // Verify contents matches input
        assert_eq!(seculog.contents, log);
    }

    #[test]
    fn parse_sniper_timestamp_ns_returns_expected_nanos() {
        let ns = parse_sniper_timestamp_ns("2024/01/02 03:04:05").unwrap();
        assert_eq!(ns, 1_704_132_245_000_000_000);
    }

    #[test]
    fn test_parse_sniper_timestamp_midnight() {
        let ns = parse_sniper_timestamp_ns("2024/01/01 00:00:00").unwrap();
        assert_eq!(ns, 1_704_034_800_000_000_000); // 2023-12-31 15:00:00 UTC
    }

    #[test]
    fn test_parse_sniper_timestamp_end_of_day() {
        let ns = parse_sniper_timestamp_ns("2023/12/31 23:59:59").unwrap();
        assert_eq!(ns, 1_704_034_799_000_000_000); // 14:59:59 UTC
    }

    #[test]
    fn test_parse_sniper_timestamp_leap_day() {
        let ns = parse_sniper_timestamp_ns("2024/02/29 12:00:00").unwrap();
        assert_eq!(ns, 1_709_175_600_000_000_000); // 03:00:00 UTC
    }

    #[test]
    fn test_parse_sniper_timestamp_invalid_date() {
        assert!(parse_sniper_timestamp_ns("2023/02/30 12:00:00").is_err());
    }

    #[test]
    fn test_parse_sniper_timestamp_invalid_month() {
        assert!(parse_sniper_timestamp_ns("2023/13/15 12:00:00").is_err());
    }

    #[test]
    fn test_parse_sniper_timestamp_invalid_hour() {
        assert!(parse_sniper_timestamp_ns("2023/01/15 24:00:00").is_err());
    }

    #[test]
    fn test_parse_sniper_timestamp_invalid_format() {
        assert!(parse_sniper_timestamp_ns("2023-01-15 12:00:00").is_err());
    }

    #[test]
    fn test_parse_sniper_timestamp_empty() {
        assert!(parse_sniper_timestamp_ns("").is_err());
    }
}
