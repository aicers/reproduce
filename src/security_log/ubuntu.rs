use std::sync::OnceLock;

use anyhow::{anyhow, bail, Context, Result};
use giganto_client::ingest::log::SecuLog;
use jiff::Timestamp;
use regex::Regex;

use super::{timestamp_to_i64, ParseSecurityLog, SecurityLogInfo, Ubuntu};

fn get_ubuntu_regex() -> &'static Regex {
    static LOG_REGEX: OnceLock<Regex> = OnceLock::new();

    LOG_REGEX
        .get_or_init(|| Regex::new(r"(?<datetime>\w{3} \d{1,2} \d{2}:\d{2}:\d{2})").expect("regex"))
}

fn parse_ubuntu_timestamp(datetime: &str) -> Result<Timestamp> {
    let current_year = Timestamp::now()
        .strftime("%Y")
        .to_string()
        .parse::<i32>()
        .map_err(|e| anyhow!("failed to parse current year: {e}"))?;
    Timestamp::strptime(
        "%Y %b %d %H:%M:%S %z",
        format!("{current_year} {datetime} +0900"),
    )
    .map_err(|e| anyhow!("{e:?}"))
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

        let timestamp = timestamp_to_i64(parse_ubuntu_timestamp(datetime)?)
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
