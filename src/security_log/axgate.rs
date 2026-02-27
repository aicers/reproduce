use std::{net::IpAddr, str::FromStr, sync::OnceLock};

use anyhow::{Context, Result, anyhow, bail};
use giganto_client::ingest::log::SecuLog;
use jiff::Timestamp;
use regex::Regex;

use super::{Axgate, DEFAULT_IPADDR, DEFAULT_PORT, PROTO_TCP, ParseSecurityLog, SecurityLogInfo};

fn get_axgate_regex() -> &'static Regex {
    static LOG_REGEX: OnceLock<Regex> = OnceLock::new();

    LOG_REGEX.get_or_init(|| {
        Regex::new(r"time:(?<datetime>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*?src:(?<srcIp>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?dst:(?<dstIp>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?sport:(?<srcPort>\d+).*?dport:(?<dstPort>\d+).*?proto:(?<proto>\d+)")
            .expect("regex")
    })
}

fn parse_axgate_timestamp_ns(datetime: &str) -> Result<i64> {
    Timestamp::strptime("%Y-%m-%d %H:%M:%S %z", format!("{datetime} +0900"))
        .map_err(|e| anyhow!("{e:?}"))?
        .as_nanosecond()
        .try_into()
        .map_err(|e| anyhow!("{e:?}"))
}

impl ParseSecurityLog for Axgate {
    fn parse_security_log(
        line: &str,
        serial: i64,
        info: SecurityLogInfo,
    ) -> Result<(SecuLog, i64)> {
        let caps = get_axgate_regex()
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
            Some(d) => d.as_str().parse::<u8>().unwrap_or(PROTO_TCP),
            None => PROTO_TCP,
        };

        let timestamp = parse_axgate_timestamp_ns(datetime)? + serial;

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
    use std::net::Ipv4Addr;

    use super::*;
    use crate::security_log::PROTO_UDP;

    #[test]
    fn parse_axgate_rejects_invalid_format() {
        let info = SecurityLogInfo {
            kind: "axgate".to_string(),
            log_type: "fw".to_string(),
            version: "2.0".to_string(),
        };

        // Empty string should fail
        assert!(Axgate::parse_security_log("", 0, info.clone()).is_err());

        // Random garbage should fail
        assert!(Axgate::parse_security_log("random garbage", 0, info.clone()).is_err());

        // Truncated log missing required fields should fail
        let truncated =
            "Aug 11 13:07:17 106.243.158.126 time:2021-08-11 13:07:18,src:192.168.0.234";
        assert!(Axgate::parse_security_log(truncated, 0, info).is_err());
    }

    #[test]
    fn parse_axgate_maps_fields_correctly() {
        let info = SecurityLogInfo {
            kind: "axgate".to_string(),
            log_type: "fw".to_string(),
            version: "2.0".to_string(),
        };

        let log = "Aug 11 13:07:17 106.243.158.126 Aug 11 13:07:18 amnet kernel: ver:3,time:2021-08-11 13:07:18,src:192.168.0.234,nat_src:106.243.158.126,dst:208.91.112.52,nat_dst:0.0.0.0,priority:medium,sport:57879,nat_sport:57879,dport:53,nat_dport:0,proto:17,sid:1551,category:application,action:pass,count:1,sessid:63760071,npdump:0,id:404,prof_id:1,nat_type:s,snat_id:500,dnat_id:0,uid:-,stime:2021-08-11 13:02:35,etime:- -,s_pkts:54,s_bytes:4122,r_pkts:53,r_bytes:8953,rule_ver:4,f_zone:trust,t_zone:untrust,vd_id:0,rule_pri:25,rule_id:27,pdir:to-src,message:APPLICATION DNS Spoof query response with TTL of 1 min. and no authority";

        let serial: i64 = 42;
        let (seculog, timestamp) = Axgate::parse_security_log(log, serial, info).unwrap();

        // Verify kind, log_type, version from info
        assert_eq!(seculog.kind, "axgate");
        assert_eq!(seculog.log_type, "fw");
        assert_eq!(seculog.version, "2.0");

        // Verify parsed IP addresses
        assert_eq!(
            seculog.orig_addr,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 234)))
        );
        assert_eq!(
            seculog.resp_addr,
            Some(IpAddr::V4(Ipv4Addr::new(208, 91, 112, 52)))
        );

        // Verify ports
        assert_eq!(seculog.orig_port, Some(57879));
        assert_eq!(seculog.resp_port, Some(53));

        // Verify protocol is UDP (17)
        assert_eq!(seculog.proto, Some(PROTO_UDP));

        // Verify timestamp matches expected value (datetime + serial offset)
        // "2021-08-11 13:07:18" +0900 = 2021-08-11 04:07:18 UTC = 1628654838 seconds since epoch
        assert_eq!(timestamp, 1_628_654_838_000_000_000 + serial);

        // Verify contents matches input
        assert_eq!(seculog.contents, log);
    }

    #[test]
    fn parse_axgate_timestamp_ns_returns_expected_nanos() {
        let ns = parse_axgate_timestamp_ns("2024-01-02 03:04:05").unwrap();
        assert_eq!(ns, 1_704_132_245_000_000_000);
    }

    #[test]
    fn test_parse_axgate_timestamp_midnight() {
        let ns = parse_axgate_timestamp_ns("2024-01-01 00:00:00").unwrap();
        assert_eq!(ns, 1_704_034_800_000_000_000); // 2023-12-31 15:00:00 UTC
    }

    #[test]
    fn test_parse_axgate_timestamp_end_of_day() {
        let ns = parse_axgate_timestamp_ns("2023-12-31 23:59:59").unwrap();
        assert_eq!(ns, 1_704_034_799_000_000_000); // 14:59:59 UTC
    }

    #[test]
    fn test_parse_axgate_timestamp_leap_day() {
        let ns = parse_axgate_timestamp_ns("2024-02-29 12:00:00").unwrap();
        assert_eq!(ns, 1_709_175_600_000_000_000); // 03:00:00 UTC
    }

    #[test]
    fn test_parse_axgate_timestamp_invalid_date() {
        assert!(parse_axgate_timestamp_ns("2023-02-30 12:00:00").is_err());
    }

    #[test]
    fn test_parse_axgate_timestamp_invalid_month() {
        assert!(parse_axgate_timestamp_ns("2023-13-15 12:00:00").is_err());
    }

    #[test]
    fn test_parse_axgate_timestamp_invalid_hour() {
        assert!(parse_axgate_timestamp_ns("2023-01-15 24:00:00").is_err());
    }

    #[test]
    fn test_parse_axgate_timestamp_invalid_format() {
        assert!(parse_axgate_timestamp_ns("2023/01/15 12:00:00").is_err());
    }

    #[test]
    fn test_parse_axgate_timestamp_empty() {
        assert!(parse_axgate_timestamp_ns("").is_err());
    }
}
