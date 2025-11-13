use std::{net::IpAddr, str::FromStr, sync::OnceLock};

use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, Utc};
use giganto_client::ingest::log::SecuLog;
use regex::Regex;

use super::{DEFAULT_IPADDR, Nginx, ParseSecurityLog, SecurityLogInfo, datetime_to_nanos};

fn get_nginx_regex() -> &'static Regex {
    static LOG_REGEX: OnceLock<Regex> = OnceLock::new();

    LOG_REGEX.get_or_init(|| {
        Regex::new(r"(?<srcIp>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?(?<datetime>\d{1,2}\/\w{3}\/\d{4}:\d{2}:\d{2}:\d{2} \+\d{4})")
            .expect("regex")
    })
}

fn parse_nginx_timestamp(datetime: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_str(datetime, "%d/%b/%Y:%T %z")
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| anyhow!("{e:?}"))
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

        let orig_addr = match caps.name("srcIp") {
            Some(d) => IpAddr::from_str(d.as_str()).unwrap_or(DEFAULT_IPADDR),
            None => DEFAULT_IPADDR,
        };

        let timestamp = datetime_to_nanos(parse_nginx_timestamp(datetime)?)? + serial;

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
    use chrono::{DateTime, Utc};

    use super::parse_nginx_timestamp;

    #[test]
    fn nginx_timestamp_parses_with_offset() {
        let ts = parse_nginx_timestamp("09/Jan/2020:09:26:09 +0900").unwrap();
        let expected = DateTime::parse_from_str("09/Jan/2020:09:26:09 +0900", "%d/%b/%Y:%T %z")
            .expect("valid timestamp")
            .with_timezone(&Utc);
        assert_eq!(ts, expected);
    }

    #[test]
    fn nginx_timestamp_rejects_invalid_input() {
        assert!(parse_nginx_timestamp("13/NotAMonth/2020:09:26:09 +0900").is_err());
    }
}
