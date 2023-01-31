use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Utc};
use giganto_client::ingest::log::{OpLogLevel, Oplog};
use lazy_static::lazy_static;
use regex::Regex;
use std::str::FromStr;

fn parse_oplog_timestamp(datetime: &str) -> Result<DateTime<Utc>> {
    DateTime::from_str(datetime).map_err(|e| anyhow!("{:?}", e))
}

fn parse_log_level(level: &str) -> Result<OpLogLevel> {
    match level {
        "INFO" => Ok(OpLogLevel::Info),
        "WARN" => Ok(OpLogLevel::Warn),
        "ERROR" => Ok(OpLogLevel::Error),
        _ => Err(anyhow!("invalid log level")),
    }
}

pub(crate) fn log_regex(line: &str, agent: &str) -> Result<(Oplog, i64)> {
    lazy_static! {
        static ref LOG_REGEX: Regex =
            Regex::new(r"(?P<datetime>\S+)\s+(?P<level>INFO|WARN|ERROR)\s(?P<contents>.+)$")
                .expect("regex");
    }
    let caps = LOG_REGEX.captures(line).context("invalid log line")?;

    let log_level = match caps.name("level") {
        Some(l) => l.as_str(),
        None => bail!("invalid log level"),
    };
    let log_level = parse_log_level(log_level)?;

    let datetime = match caps.name("datetime") {
        Some(d) => d.as_str(),
        None => bail!("invalid datetime"),
    };
    let timestamp = parse_oplog_timestamp(datetime)?.timestamp_nanos();

    let log = match caps.name("contents") {
        Some(l) => l.as_str(),
        None => "Unreachable",
    };

    Ok((
        Oplog {
            agent_name: agent.to_string(),
            log_level,
            contents: log.to_string(),
        },
        timestamp,
    ))
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};

    use super::{log_regex, OpLogLevel};

    #[test]
    fn parse_oplog() {
        let line_info = "2023-01-02T07:36:17Z  INFO infolog";
        let line_warn = "2023-01-02T07:36:17.123123Z  WARN warnlog";
        let line_error = "2023-01-02T07:36:17.789789Z  ERROR errorlog";
        let invalid_log = "hello";
        let invalid_dt = "NOT_DATETIME  INFO infolog";
        let invalid_level = "2023-01-02T07:36:17.123123Z TRACE infolog";
        let no_contents = "2023-01-02T07:36:17.123123Z  INFO ";

        let (res_info, dt) = log_regex(line_info, "agent").unwrap();
        let (res_warn, _) = log_regex(line_warn, "agent").unwrap();
        let (res_error, _) = log_regex(line_error, "agent").unwrap();

        assert!(log_regex(invalid_log, "agent").is_err());
        assert!(log_regex(invalid_dt, "agent").is_err());
        assert!(log_regex(invalid_level, "agent").is_err());
        assert!(log_regex(no_contents, "agent").is_err());
        assert_eq!(
            dt,
            Utc.with_ymd_and_hms(2023, 1, 2, 7, 36, 17)
                .unwrap()
                .timestamp_nanos()
        );
        assert_eq!(res_info.agent_name, "agent".to_string());
        assert!(matches!(res_info.log_level, OpLogLevel::Info));
        assert_eq!(res_info.contents, "infolog".to_string());

        assert_eq!(res_warn.agent_name, "agent".to_string());
        assert!(matches!(res_warn.log_level, OpLogLevel::Warn));
        assert_eq!(res_warn.contents, "warnlog".to_string());

        assert_eq!(res_error.agent_name, "agent".to_string());
        assert!(matches!(res_error.log_level, OpLogLevel::Error));
        assert_eq!(res_error.contents, "errorlog".to_string());
    }
}
