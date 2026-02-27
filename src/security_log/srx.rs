use std::{net::IpAddr, str::FromStr, sync::OnceLock};

use anyhow::{Context, Result, anyhow, bail};
use giganto_client::ingest::log::SecuLog;
use jiff::Timestamp;
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
    Timestamp::strptime("%Y-%m-%dT%H:%M:%S%.f%:z", datetime)
        .map_err(|e| anyhow!("{e:?}"))?
        .as_nanosecond()
        .try_into()
        .map_err(|e| anyhow!("{e:?}"))
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
    use std::net::Ipv4Addr;

    use super::*;
    use crate::security_log::PROTO_TCP;

    #[test]
    fn parse_srx_rejects_invalid_format() {
        let info = SecurityLogInfo {
            kind: "srx".to_string(),
            log_type: "ips".to_string(),
            version: "15.1".to_string(),
        };

        // Empty string should fail
        assert!(Srx::parse_security_log("", 0, info.clone()).is_err());

        // Random garbage should fail
        assert!(Srx::parse_security_log("random garbage", 0, info.clone()).is_err());

        // Truncated log missing required fields should fail
        let truncated = r"<14>1 2019-05-10T17:31:09.856+09:00 Saeki_PNC_SRX340 RT_IDP";
        assert!(Srx::parse_security_log(truncated, 0, info).is_err());
    }

    #[test]
    fn parse_srx_maps_fields_correctly() {
        let info = SecurityLogInfo {
            kind: "srx".to_string(),
            log_type: "ips".to_string(),
            version: "15.1".to_string(),
        };

        let log = r#"<14>1 2019-05-10T17:31:09.856+09:00 Saeki_PNC_SRX340 RT_IDP - IDP_ATTACK_LOG_EVENT [junos@2636.1.1.1.2.135 epoch-time="1557477065" message-type="ANOMALY" source-address="211.192.8.240" source-port="8071" destination-address="13.124.252.139" destination-port="80" protocol-name="TCP" service-name="HTTP" application-name="HTTP" rule-name="1" rulebase-name="IPS" policy-name="UTM" export-id="1716" repeat-count="3" action="NONE" threat-severity="HIGH" attack-name="HTTP:OVERFLOW:URL-OVERFLOW" nat-source-address="0.0.0.0" nat-source-port="0" nat-destination-address="0.0.0.0" nat-destination-port="0" elapsed-time="0" inbound-bytes="0" outbound-bytes="0" inbound-packets="0" outbound-packets="0" source-zone-name="trust" source-interface-name="ge-0/0/1.0" destination-zone-name="untrust" destination-interface-name="ge-0/0/0.0" packet-log-id="0" alert="no" username="N/A" roles="N/A" message="-"]"#;

        let serial: i64 = 42;
        let (seculog, timestamp) = Srx::parse_security_log(log, serial, info).unwrap();

        // Verify kind, log_type, version from info
        assert_eq!(seculog.kind, "srx");
        assert_eq!(seculog.log_type, "ips");
        assert_eq!(seculog.version, "15.1");

        // Verify parsed IP addresses
        assert_eq!(
            seculog.orig_addr,
            Some(IpAddr::V4(Ipv4Addr::new(211, 192, 8, 240)))
        );
        assert_eq!(
            seculog.resp_addr,
            Some(IpAddr::V4(Ipv4Addr::new(13, 124, 252, 139)))
        );

        // Verify ports
        assert_eq!(seculog.orig_port, Some(8071));
        assert_eq!(seculog.resp_port, Some(80));

        // Verify protocol is TCP
        assert_eq!(seculog.proto, Some(PROTO_TCP));

        // Verify timestamp matches expected value (datetime + serial offset)
        // "2019-05-10T17:31:09.856+09:00" = 2019-05-10 08:31:09.856 UTC = 1557477069.856 seconds since epoch
        assert_eq!(timestamp, 1_557_477_069_856_000_000 + serial);

        // Verify contents matches input
        assert_eq!(seculog.contents, log);
    }

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
