use std::{net::IpAddr, str::FromStr, sync::OnceLock};

use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, Utc};
use giganto_client::ingest::log::SecuLog;
use regex::Regex;

use super::{
    DEFAULT_IPADDR, DEFAULT_PORT, Mf2, ParseSecurityLog, SecurityLogInfo, datetime_to_nanos,
    proto_to_u8,
};

fn get_mf2_regex() -> &'static Regex {
    static LOG_REGEX: OnceLock<Regex> = OnceLock::new();

    LOG_REGEX.get_or_init(|| {
        Regex::new(r"\](?P<datetime>\d{4}\-\d{1,2}\-\d{1,2} \d{2}:\d{2}:\d{2}),.*?,(?P<srcIp>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),(?P<srcPort>\d+),(?P<dstIp>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),(?P<dstPort>\d+),(?P<proto>\w+),")
            .expect("regex")
    })
}

fn parse_mf2_timestamp(datetime: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_str(&format!("{datetime} +0900"), "%Y-%m-%d %H:%M:%S %z")
        .map(|dt| dt.with_timezone(&Utc))
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

        let timestamp = datetime_to_nanos(parse_mf2_timestamp(datetime)?)? + serial;

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
    use chrono::{DateTime, Utc};

    use super::parse_mf2_timestamp;

    #[test]
    fn mf2_timestamp_applies_kst_offset() {
        let ts = parse_mf2_timestamp("2020-07-13 09:33:23").unwrap();
        let expected =
            DateTime::parse_from_str("2020-07-13 09:33:23 +0900", "%Y-%m-%d %H:%M:%S %z")
                .expect("valid timestamp")
                .with_timezone(&Utc);
        assert_eq!(ts, expected);
    }

    #[test]
    fn mf2_timestamp_rejects_invalid_input() {
        assert!(parse_mf2_timestamp("2020-99-99 25:61:61").is_err());
    }
}
