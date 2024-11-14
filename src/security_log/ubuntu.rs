use std::sync::OnceLock;

use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Datelike, FixedOffset, Utc};
use giganto_client::ingest::log::SecuLog;
use regex::Regex;

use super::{ParseSecurityLog, SecurityLogInfo, Ubuntu};

fn get_ubuntu_regex() -> &'static Regex {
    static LOG_REGEX: OnceLock<Regex> = OnceLock::new();

    LOG_REGEX
        .get_or_init(|| Regex::new(r"(?<datetime>\w{3} \d{1,2} \d{2}:\d{2}:\d{2})").expect("regex"))
}

fn parse_ubuntu_timestamp(datetime: &str) -> Result<DateTime<FixedOffset>> {
    let now = Utc::now();
    DateTime::parse_from_str(
        &format!("{} {datetime} +0900", now.year()),
        "%Y %b %d %H:%M:%S %z",
    )
    .map_err(|e| anyhow!("{:?}", e))
}

impl ParseSecurityLog for Ubuntu {
    fn parse_security_log(
        line: &str,
        serial: i64,
        info: SecurityLogInfo,
    ) -> Result<(SecuLog, i64)> {
        let caps = get_ubuntu_regex()
            .captures(line)
            .context("invalid log line")?;

        let datetime = match caps.name("datetime") {
            Some(d) => d.as_str(),
            None => bail!("invalid datetime"),
        };

        let timestamp = parse_ubuntu_timestamp(datetime)?
            .timestamp_nanos_opt()
            .context("to_timestamp_nanos")?
            + serial;

        Ok((
            SecuLog {
                kind: info.kind,
                log_type: info.log_type,
                version: info.version,
                orig_addr: None,
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
