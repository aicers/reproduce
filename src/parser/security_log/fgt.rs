use std::{net::IpAddr, str::FromStr, sync::OnceLock};

use anyhow::{Context, Result, anyhow, bail};
use giganto_client::ingest::log::SecuLog;
use jiff::Timestamp;
use regex::Regex;

use super::{DEFAULT_IPADDR, DEFAULT_PORT, Fgt, PROTO_TCP, ParseSecurityLog, SecurityLogInfo};

fn get_fgt_regex() -> &'static Regex {
    static LOG_REGEX: OnceLock<Regex> = OnceLock::new();

    LOG_REGEX.get_or_init(|| {
        Regex::new(r#"date=(?<date>\d{4}-\d{2}-\d{2}) time=(?<time>\d{2}:\d{2}:\d{2}).*?tz="(?<tz>\+\d{4})".*? srcip=(?<srcIp>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*dstip=(?<dstIp>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*proto=(?<proto>\d+).*srcport=(?<srcPort>\d+) dstport=(?<dstPort>\d+)"#)
            .expect("regex")
    })
}

fn parse_fgt_timestamp_ns(date: &str, time: &str, tz: &str) -> Result<i64> {
    Timestamp::strptime("%Y-%m-%d %H:%M:%S %z", format!("{date} {time} {tz}"))
        .map_err(|e| anyhow!("{e:?}"))?
        .as_nanosecond()
        .try_into()
        .map_err(|e| anyhow!("{e:?}"))
}

impl ParseSecurityLog for Fgt {
    fn parse_security_log(
        line: &str,
        serial: i64,
        info: SecurityLogInfo,
    ) -> Result<(SecuLog, i64)> {
        let caps = get_fgt_regex().captures(line).context("invalid log line")?;

        let date = match caps.name("date") {
            Some(d) => d.as_str(),
            None => bail!("invalid date"),
        };
        let time = match caps.name("time") {
            Some(d) => d.as_str(),
            None => bail!("invalid time"),
        };
        let tz = match caps.name("tz") {
            Some(d) => d.as_str(),
            None => bail!("invalid tz"),
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

        let timestamp = parse_fgt_timestamp_ns(date, time, tz)? + serial;

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

    #[test]
    fn parse_fgt_rejects_invalid_format() {
        let info = SecurityLogInfo {
            kind: "fgt".to_string(),
            log_type: "ips".to_string(),
            version: "5.2".to_string(),
        };

        // Empty string should fail
        assert!(Fgt::parse_security_log("", 0, info.clone()).is_err());

        // Random garbage should fail
        assert!(Fgt::parse_security_log("random garbage", 0, info.clone()).is_err());

        // Truncated log missing required fields should fail
        let truncated = r#"<185>date=2020-07-13 time=09:37:44 devname="Chamhosp_201E""#;
        assert!(Fgt::parse_security_log(truncated, 0, info).is_err());
    }

    #[test]
    fn parse_fgt_maps_fields_correctly() {
        let info = SecurityLogInfo {
            kind: "fgt".to_string(),
            log_type: "ips".to_string(),
            version: "5.2".to_string(),
        };

        let log = r#"<185>date=2020-07-13 time=09:37:44 devname="Chamhosp_201E" devid="FG201ETK19907629" logid="0419016384" type="utm" subtype="ips" eventtype="signature" level="alert" vd="root" eventtime=1594600665469973652 tz="+0900" severity="medium" srcip=10.10.40.132 srccountry="Reserved" dstip=10.10.40.245 srcintf="port13" srcintfrole="undefined" dstintf="port13" dstintfrole="undefined" sessionid=78411987 action="dropped" proto=6 service="NBSS" policyid=1 attack="MS.SMB.Server.Trans.Peeking.Data.Information.Disclosure" srcport=62227 dstport=445 direction="outgoing" attackid=43799 profile="sniffer-profile" ref="http://www.fortinet.com/ids/VID43799" incidentserialno=1038270373 msg="applications3: MS.SMB.Server.Trans.Peeking.Data.Information.Disclosure," crscore=10 craction=16384 crlevel="medium""#;

        let serial: i64 = 42;
        let (seculog, timestamp) = Fgt::parse_security_log(log, serial, info).unwrap();

        // Verify kind, log_type, version from info
        assert_eq!(seculog.kind, "fgt");
        assert_eq!(seculog.log_type, "ips");
        assert_eq!(seculog.version, "5.2");

        // Verify parsed IP addresses
        assert_eq!(
            seculog.orig_addr,
            Some(IpAddr::V4(Ipv4Addr::new(10, 10, 40, 132)))
        );
        assert_eq!(
            seculog.resp_addr,
            Some(IpAddr::V4(Ipv4Addr::new(10, 10, 40, 245)))
        );

        // Verify ports
        assert_eq!(seculog.orig_port, Some(62227));
        assert_eq!(seculog.resp_port, Some(445));

        // Verify protocol is TCP (6)
        assert_eq!(seculog.proto, Some(PROTO_TCP));

        // Verify timestamp matches expected value (datetime + serial offset)
        // "2020-07-13 09:37:44" +0900 = 2020-07-13 00:37:44 UTC = 1594600664 seconds since epoch
        assert_eq!(timestamp, 1_594_600_664_000_000_000 + serial);

        // Verify contents matches input
        assert_eq!(seculog.contents, log);
    }

    #[test]
    fn parse_fgt_timestamp_ns_returns_expected_nanos() {
        let ns = parse_fgt_timestamp_ns("2024-01-02", "03:04:05", "+0900").unwrap();
        assert_eq!(ns, 1_704_132_245_000_000_000);
    }

    #[test]
    fn test_parse_fgt_timestamp_midnight() {
        let ns = parse_fgt_timestamp_ns("2024-01-01", "00:00:00", "+0900").unwrap();
        assert_eq!(ns, 1_704_034_800_000_000_000); // 2024-01-01 00:00:00 +0900 is 2023-12-31 15:00:00 UTC
    }

    #[test]
    fn test_parse_fgt_timestamp_end_of_day() {
        let ns = parse_fgt_timestamp_ns("2023-12-31", "23:59:59", "+0900").unwrap();
        assert_eq!(ns, 1_704_034_799_000_000_000); // 2023-12-31 23:59:59 +0900 is 2023-12-31 14:59:59 UTC
    }

    #[test]
    fn test_parse_fgt_timestamp_leap_day() {
        let ns = parse_fgt_timestamp_ns("2024-02-29", "12:00:00", "+0900").unwrap();
        assert_eq!(ns, 1_709_175_600_000_000_000); // 2024-02-29 12:00:00 +0900 is 03:00:00 UTC
    }

    #[test]
    fn test_parse_fgt_timestamp_invalid_date() {
        assert!(parse_fgt_timestamp_ns("2023-02-30", "12:00:00", "+0900").is_err());
    }

    #[test]
    fn test_parse_fgt_timestamp_invalid_month() {
        assert!(parse_fgt_timestamp_ns("2023-13-15", "12:00:00", "+0900").is_err());
    }

    #[test]
    fn test_parse_fgt_timestamp_invalid_hour() {
        assert!(parse_fgt_timestamp_ns("2023-01-15", "24:00:00", "+0900").is_err());
    }

    #[test]
    fn test_parse_fgt_timestamp_invalid_format() {
        // Since arguments are splits, invalid format mainly means the strings themselves don't parse
        assert!(parse_fgt_timestamp_ns("2023/01/15", "12:00:00", "+0900").is_err());
    }

    #[test]
    fn test_parse_fgt_timestamp_empty() {
        assert!(parse_fgt_timestamp_ns("", "", "").is_err());
    }
}
