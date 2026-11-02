mod dns_query;
mod file_create;
mod file_create_stream_hash;
mod file_create_time;
mod file_delete;
mod file_delete_detected;
mod image_load;
mod network_connect;
mod pipe_event;
mod process_create;
mod process_tamper;
mod process_terminate;
mod registry_key_rename;
mod registry_value_set;

use std::{fs::File, path::Path};

use anyhow::{Context, anyhow};
use csv::{Reader, ReaderBuilder, StringRecord};
use jiff::{Timestamp, tz::TimeZone};
use thiserror::Error;

#[derive(Debug, Error)]
#[error(transparent)]
pub struct SysmonCsvError(anyhow::Error);

impl From<anyhow::Error> for SysmonCsvError {
    fn from(error: anyhow::Error) -> Self {
        Self(error)
    }
}

pub type SysmonCsvResult<T> = std::result::Result<T, SysmonCsvError>;

/// Parses a Sysmon time string (`YYYY-MM-DD HH:MM:SS.fff`) into a UTC `Timestamp`.
///
/// # Errors
///
/// Returns an error if the time string is malformed.
pub fn parse_sysmon_time(time: &str) -> SysmonCsvResult<Timestamp> {
    let dt = jiff::civil::DateTime::strptime("%Y-%m-%d %H:%M:%S%.f", time)
        .map_err(|_| anyhow!("invalid time: {time}"))?;
    Ok(dt
        .to_zoned(TimeZone::UTC)
        .map_err(|e| anyhow!("failed to create zoned datetime: {e}"))
        .map(|z| z.timestamp())?)
}

/// Parses a Sysmon time string into nanoseconds since the Unix epoch.
///
/// # Errors
///
/// Returns an error if the time string is malformed or overflows.
pub fn parse_sysmon_timestamp_ns(time: &str) -> SysmonCsvResult<i64> {
    let ts = parse_sysmon_time(time)?;
    Ok(i64::try_from(ts.as_nanosecond()).context("timestamp nanoseconds overflow")?)
}

/// Opens a Sysmon CSV file and returns a configured CSV reader.
///
/// # Errors
///
/// Returns an error if the file cannot be opened.
pub fn open_sysmon_csv_file(path: &Path) -> SysmonCsvResult<Reader<File>> {
    Ok(ReaderBuilder::new()
        .comment(Some(b'#'))
        .delimiter(b'\t')
        .flexible(true)
        .from_path(path)
        .map_err(anyhow::Error::from)?)
}

/// Converts a Sysmon CSV record into a typed event.
pub trait TryFromSysmonRecord: Sized {
    /// Parses the record and returns the typed event with its raw timestamp.
    ///
    /// # Errors
    ///
    /// Returns an error if the record cannot be parsed.
    fn try_from_sysmon_record(rec: &StringRecord) -> SysmonCsvResult<(Self, i64)>;
}

#[cfg(test)]
mod sysmon_timestamp_tests {
    use super::*;

    #[test]
    fn test_parse_sysmon_time_valid() {
        // Valid timestamp with microseconds
        let result = parse_sysmon_time("2023-01-15 14:30:45.123456");
        assert!(result.is_ok());
        let ts = result.unwrap();
        let zoned = ts.to_zoned(TimeZone::UTC);
        assert_eq!(zoned.year(), 2023);
        assert_eq!(zoned.month(), 1);
        assert_eq!(zoned.day(), 15);
        assert_eq!(zoned.hour(), 14);
        assert_eq!(zoned.minute(), 30);
        assert_eq!(zoned.second(), 45);
    }

    #[test]
    fn test_parse_sysmon_time_no_subseconds() {
        // Timestamp without fractional seconds
        let result = parse_sysmon_time("2023-01-15 14:30:45");
        assert!(result.is_ok());
        let ts = result.unwrap();
        assert_eq!(ts.subsec_nanosecond(), 0);
    }

    #[test]
    fn test_parse_sysmon_time_milliseconds() {
        // Timestamp with milliseconds only
        let result = parse_sysmon_time("2023-01-15 14:30:45.123");
        assert!(result.is_ok());
        let ts = result.unwrap();
        assert_eq!(ts.subsec_millisecond(), 123);
    }

    #[test]
    fn test_parse_sysmon_time_nanoseconds() {
        // Timestamp with full nanosecond precision
        let result = parse_sysmon_time("2023-01-15 14:30:45.123456789");
        assert!(result.is_ok());
        let ts = result.unwrap();
        assert_eq!(ts.subsec_nanosecond(), 123_456_789);
    }

    #[test]
    fn test_parse_sysmon_time_midnight() {
        // Midnight timestamp
        let result = parse_sysmon_time("2023-01-15 00:00:00.000000");
        assert!(result.is_ok());
        let ts = result.unwrap();
        let zoned = ts.to_zoned(TimeZone::UTC);
        assert_eq!(zoned.hour(), 0);
        assert_eq!(zoned.minute(), 0);
        assert_eq!(zoned.second(), 0);
    }

    #[test]
    fn test_parse_sysmon_time_end_of_day() {
        // End of day timestamp
        let result = parse_sysmon_time("2023-01-15 23:59:59.999999");
        assert!(result.is_ok());
        let ts = result.unwrap();
        let zoned = ts.to_zoned(TimeZone::UTC);
        assert_eq!(zoned.hour(), 23);
        assert_eq!(zoned.minute(), 59);
        assert_eq!(zoned.second(), 59);
    }

    #[test]
    fn test_parse_sysmon_time_leap_day() {
        // Leap day: February 29, 2024
        let result = parse_sysmon_time("2024-02-29 12:00:00.000000");
        assert!(result.is_ok());
        let ts = result.unwrap();
        let zoned = ts.to_zoned(TimeZone::UTC);
        assert_eq!(zoned.year(), 2024);
        assert_eq!(zoned.month(), 2);
        assert_eq!(zoned.day(), 29);
    }

    #[test]
    fn test_parse_sysmon_time_invalid_date() {
        // Invalid date: February 30
        let result = parse_sysmon_time("2023-02-30 12:00:00.000000");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_sysmon_time_invalid_month() {
        // Invalid month: 13
        let result = parse_sysmon_time("2023-13-15 12:00:00.000000");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_sysmon_time_invalid_hour() {
        // Invalid hour: 24
        let result = parse_sysmon_time("2023-01-15 24:00:00.000000");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_sysmon_time_invalid_format() {
        // Wrong format
        let result = parse_sysmon_time("2023/01/15 14:30:45");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_sysmon_time_empty_string() {
        // Empty string
        let result = parse_sysmon_time("");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_sysmon_time_conversion_to_nanos() {
        // Verify nanosecond conversion
        let result = parse_sysmon_time("2023-01-15 14:30:45.123456");
        assert!(result.is_ok());
        let ts = result.unwrap();
        let nanos = i64::try_from(ts.as_nanosecond());
        assert!(nanos.is_ok());
    }

    #[test]
    fn test_parse_sysmon_timestamp_ns_returns_nanoseconds() {
        let ns = parse_sysmon_timestamp_ns("2023-08-08 07:51:14.875").unwrap();
        assert_eq!(ns, 1_691_481_074_875_000_000);
    }

    #[test]
    fn test_parse_sysmon_timestamp_ns_rejects_invalid_input() {
        assert!(parse_sysmon_timestamp_ns("invalid").is_err());
    }
}
