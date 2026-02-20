use std::{net::IpAddr, str::FromStr, sync::OnceLock};

use anyhow::{Context, Result, bail};
use giganto_client::ingest::log::SecuLog;
use regex::Regex;

use super::{
    DEFAULT_IPADDR, DEFAULT_PORT, PROTO_TCP, ParseSecurityLog, SecurityLogInfo, ShadowWall,
};

fn get_shadow_regex() -> &'static Regex {
    static LOG_REGEX: OnceLock<Regex> = OnceLock::new();

    LOG_REGEX.get_or_init(|| {
        Regex::new(r"(?<timestamp>\d{10}).*?(?<proto>\d+)\t(?<srcIp>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\t(?<srcPort>\d+)\t(?<dstIp>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\t(?<dstPort>\d+)")
            .expect("regex")
    })
}

impl ParseSecurityLog for ShadowWall {
    fn parse_security_log(
        line: &str,
        serial: i64,
        info: SecurityLogInfo,
    ) -> Result<(SecuLog, i64)> {
        let caps = get_shadow_regex()
            .captures(line)
            .context("invalid log line")?;

        let timestamp = match caps.name("timestamp") {
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

        let timestamp = format!("{timestamp}000000000")
            .parse::<i64>()
            .unwrap_or_default()
            + serial;

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
    fn parse_shadow_wall_rejects_invalid_format() {
        let info = SecurityLogInfo {
            kind: "shadowwall".to_string(),
            log_type: "ips".to_string(),
            version: "5.0".to_string(),
        };

        // Empty string should fail
        assert!(ShadowWall::parse_security_log("", 0, info.clone()).is_err());

        // Random garbage should fail
        assert!(ShadowWall::parse_security_log("random garbage", 0, info.clone()).is_err());

        // Truncated log missing IP/port fields should fail
        let truncated = "<142>Oct 31 13:45:51 ShadowWall sm[22143]: ipslog	111363	1698727507";
        assert!(ShadowWall::parse_security_log(truncated, 0, info).is_err());
    }

    #[test]
    fn parse_shadow_wall_maps_fields_correctly() {
        let info = SecurityLogInfo {
            kind: "shadowwall".to_string(),
            log_type: "ips".to_string(),
            version: "5.0".to_string(),
        };

        let log = "<142>Oct 31 13:45:51 ShadowWall sm[22143]: ipslog	111363	1698727507	387133	0	1	DURUAN	3	1	2012937	3	ET SCAN Internal Dummy Connection User-Agent Inbound	21	1	6	159.223.48.151	44814	112.175.234.93	80";

        let serial: i64 = 42;
        let (seculog, timestamp) = ShadowWall::parse_security_log(log, serial, info).unwrap();

        // Verify kind, log_type, version from info
        assert_eq!(seculog.kind, "shadowwall");
        assert_eq!(seculog.log_type, "ips");
        assert_eq!(seculog.version, "5.0");

        // Verify parsed IP addresses
        assert_eq!(
            seculog.orig_addr,
            Some(IpAddr::V4(Ipv4Addr::new(159, 223, 48, 151)))
        );
        assert_eq!(
            seculog.resp_addr,
            Some(IpAddr::V4(Ipv4Addr::new(112, 175, 234, 93)))
        );

        // Verify ports
        assert_eq!(seculog.orig_port, Some(44814));
        assert_eq!(seculog.resp_port, Some(80));

        // Verify protocol is TCP (6)
        assert_eq!(seculog.proto, Some(PROTO_TCP));

        // Verify timestamp matches expected value (unix timestamp + serial offset)
        // 1698727507 seconds since epoch (in nanoseconds)
        assert_eq!(timestamp, 1_698_727_507_000_000_000 + serial);

        // Verify contents matches input
        assert_eq!(seculog.contents, log);
    }
}
