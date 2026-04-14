use std::sync::OnceLock;

use anyhow::{Context, anyhow};
use giganto_client::ingest::log::{OpLog, OpLogLevel};
use jiff::Timestamp;
use regex::Regex;
use thiserror::Error;

#[derive(Debug, Error)]
#[error(transparent)]
pub struct OperationLogError(anyhow::Error);

impl From<anyhow::Error> for OperationLogError {
    fn from(error: anyhow::Error) -> Self {
        Self(error)
    }
}

pub type OperationLogResult<T> = std::result::Result<T, OperationLogError>;

fn get_log_regex() -> &'static Regex {
    static LOG_REGEX: OnceLock<Regex> = OnceLock::new();

    LOG_REGEX.get_or_init(|| {
        Regex::new(r"(?P<datetime>\S+)\s+(?P<level>INFO|WARN|ERROR)\s(?P<contents>.+)$")
            .expect("operation log regex literal must compile")
    })
}

fn parse_oplog_timestamp(datetime: &str) -> OperationLogResult<Timestamp> {
    Ok(datetime.parse().map_err(|e| anyhow!("{e:?}"))?)
}

fn parse_log_level(level: &str) -> OperationLogResult<OpLogLevel> {
    match level {
        "INFO" => Ok(OpLogLevel::Info),
        "WARN" => Ok(OpLogLevel::Warn),
        "ERROR" => Ok(OpLogLevel::Error),
        _ => Err(anyhow!("invalid log level").into()),
    }
}

/// Parses a log line using regex and returns an `OpLog` with its timestamp.
///
/// # Errors
///
/// Returns an error if the line does not match the expected log format.
pub fn log_regex(line: &str, service_name: &str) -> OperationLogResult<(OpLog, i64)> {
    let caps = get_log_regex().captures(line).context("invalid log line")?;

    let log_level = match caps.name("level") {
        Some(l) => l.as_str(),
        None => return Err(anyhow::anyhow!("invalid log level").into()),
    };
    let log_level = parse_log_level(log_level)?;

    let datetime = match caps.name("datetime") {
        Some(d) => d.as_str(),
        None => return Err(anyhow::anyhow!("invalid datetime").into()),
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
            service_name: service_name.to_string(),
            log_level,
            contents: log.to_string(),
        },
        timestamp,
    ))
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};

    use super::{OpLogLevel, log_regex};

    #[test]
    fn parse_oplog() {
        let line_info = "2023-01-02T07:36:17Z  INFO infolog";
        let line_warn = "2023-01-02T07:36:17.123123Z  WARN warnlog";
        let line_error = "2023-01-02T07:36:17.789789Z  ERROR errorlog";
        let invalid_log = "hello";
        let invalid_dt = "NOT_DATETIME  INFO infolog";
        let invalid_level = "2023-01-02T07:36:17.123123Z TRACE infolog";
        let no_contents = "2023-01-02T07:36:17.123123Z  INFO ";

        let (res_info, dt) = log_regex(line_info, "service_name").unwrap();
        let (res_warn, _) = log_regex(line_warn, "service_name").unwrap();
        let (res_error, _) = log_regex(line_error, "service_name").unwrap();

        assert!(log_regex(invalid_log, "service_name").is_err());
        assert!(log_regex(invalid_dt, "service_name").is_err());
        assert!(log_regex(invalid_level, "service_name").is_err());
        assert!(log_regex(no_contents, "service_name").is_err());
        assert_eq!(
            dt,
            Utc.with_ymd_and_hms(2023, 1, 2, 7, 36, 17)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap()
        );
        assert_eq!(res_info.service_name, "service_name".to_string());
        assert!(matches!(res_info.log_level, OpLogLevel::Info));
        assert_eq!(res_info.contents, "infolog".to_string());
        assert_eq!(res_info.sensor, String::new());

        assert_eq!(res_warn.service_name, "service_name".to_string());
        assert!(matches!(res_warn.log_level, OpLogLevel::Warn));
        assert_eq!(res_warn.contents, "warnlog".to_string());
        assert_eq!(res_warn.sensor, String::new());

        assert_eq!(res_error.service_name, "service_name".to_string());
        assert!(matches!(res_error.log_level, OpLogLevel::Error));
        assert_eq!(res_error.contents, "errorlog".to_string());
        assert_eq!(res_error.sensor, String::new());
    }

    #[test]
    fn log_regex_valid_formats() {
        // Valid log lines with different timestamps and content formats
        let valid_lines = [
            // Basic timestamps with different log levels
            (
                "2023-01-02T07:36:17Z  INFO simple message",
                OpLogLevel::Info,
            ),
            (
                "2023-12-31T23:59:59Z  WARN warning message",
                OpLogLevel::Warn,
            ),
            (
                "2020-06-15T12:00:00Z  ERROR error message",
                OpLogLevel::Error,
            ),
            // Timestamps with subsecond precision
            (
                "2023-01-02T07:36:17.123Z  INFO with milliseconds",
                OpLogLevel::Info,
            ),
            (
                "2023-01-02T07:36:17.123456Z  WARN with microseconds",
                OpLogLevel::Warn,
            ),
            (
                "2023-01-02T07:36:17.123456789Z  ERROR with nanoseconds",
                OpLogLevel::Error,
            ),
            // Content with special characters
            (
                "2023-01-02T07:36:17Z  INFO message with spaces and numbers 123",
                OpLogLevel::Info,
            ),
            (
                "2023-01-02T07:36:17Z  WARN path: /var/log/app.log",
                OpLogLevel::Warn,
            ),
            (
                "2023-01-02T07:36:17Z  ERROR key=value, status=500",
                OpLogLevel::Error,
            ),
        ];

        for (line, expected_level) in valid_lines {
            let result = log_regex(line, "test_agent");
            assert!(result.is_ok(), "Expected valid log line: {line}");
            let (oplog, _) = result.unwrap();
            assert!(
                matches!(oplog.log_level, ref level if std::mem::discriminant(level) == std::mem::discriminant(&expected_level)),
                "Unexpected log level for: {line}"
            );
            assert_eq!(oplog.service_name, "test_agent");
        }
    }

    #[test]
    fn log_regex_invalid_formats() {
        // Invalid log lines that should return errors
        let invalid_lines = [
            // Missing components
            "",                                           // Empty line
            "   ",                                        // Whitespace only
            "INFO message without timestamp",             // Missing timestamp
            "2023-01-02T07:36:17Z message without level", // Missing level
            "2023-01-02T07:36:17Z  INFO ",                // Empty content (trailing space)
            // Invalid log levels
            "2023-01-02T07:36:17Z  DEBUG debug message", // DEBUG not supported
            "2023-01-02T07:36:17Z  TRACE trace message", // TRACE not supported
            "2023-01-02T07:36:17Z  FATAL fatal message", // FATAL not supported
            "2023-01-02T07:36:17Z  info lowercase",      // Lowercase level
            // Invalid timestamp formats
            "NOT_A_DATE  INFO message",           // Invalid timestamp
            "2023/01/02 07:36:17  INFO message",  // Wrong date format
            "01-02-2023T07:36:17Z  INFO message", // Wrong date order
        ];

        for line in invalid_lines {
            let result = log_regex(line, "agent");
            assert!(result.is_err(), "Expected error for invalid line: {line}");
        }
    }

    #[test]
    fn log_regex_preserves_agent_name() {
        // Agent name should be passed through unchanged
        let line = "2023-01-02T07:36:17Z  INFO test message";
        let agents = ["manager", "data_store", "sensor", "custom_agent"];

        for agent in agents {
            let (oplog, _) = log_regex(line, agent).unwrap();
            assert_eq!(oplog.service_name, agent);
        }
    }

    #[test]
    fn log_regex_content_extraction() {
        // Test that content is correctly extracted from log lines
        let test_cases = [
            ("2023-01-02T07:36:17Z  INFO simple", "simple"),
            (
                "2023-01-02T07:36:17Z  WARN message with multiple words",
                "message with multiple words",
            ),
            (
                "2023-01-02T07:36:17Z  ERROR   leading spaces preserved",
                "  leading spaces preserved",
            ),
        ];

        for (line, expected_content) in test_cases {
            let (oplog, _) = log_regex(line, "agent").unwrap();
            assert_eq!(oplog.contents, expected_content);
        }
    }

    #[test]
    fn log_regex_timestamp_parsing() {
        // Verify timestamp parsing with different precision levels
        let test_cases = [
            // (log line, expected nanoseconds)
            (
                "2023-01-02T07:36:17Z  INFO msg",
                Utc.with_ymd_and_hms(2023, 1, 2, 7, 36, 17)
                    .unwrap()
                    .timestamp_nanos_opt()
                    .unwrap(),
            ),
            (
                "2023-06-15T12:30:45.123Z  INFO msg",
                Utc.with_ymd_and_hms(2023, 6, 15, 12, 30, 45)
                    .unwrap()
                    .timestamp_nanos_opt()
                    .unwrap()
                    + 123_000_000, // 123 milliseconds
            ),
            (
                "2023-06-15T12:30:45.123456Z  INFO msg",
                Utc.with_ymd_and_hms(2023, 6, 15, 12, 30, 45)
                    .unwrap()
                    .timestamp_nanos_opt()
                    .unwrap()
                    + 123_456_000, // 123456 microseconds
            ),
            (
                "2023-06-15T12:30:45.123456789Z  INFO msg",
                Utc.with_ymd_and_hms(2023, 6, 15, 12, 30, 45)
                    .unwrap()
                    .timestamp_nanos_opt()
                    .unwrap()
                    + 123_456_789, // 123456789 nanoseconds
            ),
        ];

        for (line, expected_nanos) in test_cases {
            let (_, timestamp) = log_regex(line, "agent").unwrap();
            assert_eq!(
                timestamp, expected_nanos,
                "Timestamp mismatch for line: {line}"
            );
        }
    }
}
