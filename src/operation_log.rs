use std::sync::OnceLock;

use anyhow::{Context, Result, anyhow, bail};
use giganto_client::ingest::log::{OpLog, OpLogLevel};
use jiff::Timestamp;
use regex::Regex;

fn get_log_regex() -> &'static Regex {
    static LOG_REGEX: OnceLock<Regex> = OnceLock::new();

    LOG_REGEX.get_or_init(|| {
        Regex::new(r"(?P<datetime>\S+)\s+(?P<level>INFO|WARN|ERROR)\s(?P<contents>.+)$")
            .expect("regex")
    })
}

/// Parses an operation log timestamp in ISO 8601 format.
///
/// # Errors
///
/// Returns an error if:
/// * The timestamp format is invalid
/// * The timestamp value is negative (before Unix epoch)
fn parse_oplog_timestamp(datetime: &str) -> Result<Timestamp> {
    let ts: Timestamp = datetime.parse().map_err(|e| anyhow!("{e:?}"))?;
    if ts.as_second() < 0 {
        return Err(anyhow!("negative timestamp not allowed: {datetime}"));
    }
    Ok(ts)
}

fn parse_log_level(level: &str) -> Result<OpLogLevel> {
    match level {
        "INFO" => Ok(OpLogLevel::Info),
        "WARN" => Ok(OpLogLevel::Warn),
        "ERROR" => Ok(OpLogLevel::Error),
        _ => Err(anyhow!("invalid log level")),
    }
}

pub(crate) fn log_regex(line: &str, agent: &str) -> Result<(OpLog, i64)> {
    let caps = get_log_regex().captures(line).context("invalid log line")?;

    let log_level = match caps.name("level") {
        Some(l) => l.as_str(),
        None => bail!("invalid log level"),
    };
    let log_level = parse_log_level(log_level)?;

    let datetime = match caps.name("datetime") {
        Some(d) => d.as_str(),
        None => bail!("invalid datetime"),
    };
    let ts = parse_oplog_timestamp(datetime)?;
    let timestamp = i64::try_from(ts.as_nanosecond()).context("timestamp nanoseconds overflow")?;

    let log = match caps.name("contents") {
        Some(l) => l.as_str(),
        None => "Unreachable",
    };

    Ok((
        OpLog {
            sensor: String::new(),
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

    use super::{OpLogLevel, log_regex, parse_oplog_timestamp};

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
                .timestamp_nanos_opt()
                .unwrap()
        );
        assert_eq!(res_info.agent_name, "agent".to_string());
        assert!(matches!(res_info.log_level, OpLogLevel::Info));
        assert_eq!(res_info.contents, "infolog".to_string());
        assert_eq!(res_info.sensor, String::new());

        assert_eq!(res_warn.agent_name, "agent".to_string());
        assert!(matches!(res_warn.log_level, OpLogLevel::Warn));
        assert_eq!(res_warn.contents, "warnlog".to_string());
        assert_eq!(res_warn.sensor, String::new());

        assert_eq!(res_error.agent_name, "agent".to_string());
        assert!(matches!(res_error.log_level, OpLogLevel::Error));
        assert_eq!(res_error.contents, "errorlog".to_string());
        assert_eq!(res_error.sensor, String::new());
    }

    #[test]
    fn parse_oplog_timestamp_negative_rejected() {
        // Negative timestamps (before Unix epoch) are rejected
        assert!(parse_oplog_timestamp("1969-12-31T23:59:59Z").is_err());
        assert!(parse_oplog_timestamp("1960-01-01T00:00:00Z").is_err());
    }

    #[test]
    fn parse_oplog_timestamp_epoch_accepted() {
        // Unix epoch (0) should be accepted
        assert!(parse_oplog_timestamp("1970-01-01T00:00:00Z").is_ok());
    }
}
