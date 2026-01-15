mod network;
#[cfg(test)]
mod tests;

use std::{fs::File, path::Path};

use anyhow::{Context, Result, anyhow};
use csv::{Reader, ReaderBuilder, StringRecord};
use jiff::Timestamp;

const PROTO_TCP: u8 = 0x06;
const PROTO_UDP: u8 = 0x11;
const PROTO_ICMP: u8 = 0x01;

pub(crate) trait TryFromZeekRecord: Sized {
    fn try_from_zeek_record(rec: &StringRecord) -> Result<(Self, i64)>;
}

pub(crate) fn parse_zeek_timestamp(timestamp: &str) -> Result<Timestamp> {
    let (secs_str, micros_str) = timestamp
        .split_once('.')
        .ok_or_else(|| anyhow!("invalid timestamp: {timestamp}"))?;

    let secs: i64 = secs_str.parse().context("invalid timestamp")?;
    let micros: u32 = micros_str.parse().context("invalid timestamp")?;

    let nanos: i32 = i32::try_from(micros)
        .ok()
        .and_then(|m| m.checked_mul(1000))
        .context("microseconds overflow")?;

    Timestamp::new(secs, nanos).map_err(|e| anyhow!("failed to create Timestamp: {e}"))
}

pub(crate) fn parse_zeek_timestamp_ns(timestamp: &str) -> Result<i64> {
    let ts = parse_zeek_timestamp(timestamp)?;
    i64::try_from(ts.as_nanosecond()).context("timestamp nanoseconds overflow")
}

pub(crate) fn open_raw_event_log_file(path: &Path) -> Result<Reader<File>> {
    Ok(ReaderBuilder::new()
        .comment(Some(b'#'))
        .delimiter(b'\t')
        .has_headers(false)
        .flexible(true)
        .from_path(path)?)
}

#[cfg(test)]
mod zeek_timestamp_tests {
    use super::*;

    #[test]
    fn test_parse_zeek_timestamp_valid() {
        // Valid timestamp: 2019-07-02 20:45:21.655728 UTC
        let result = parse_zeek_timestamp("1562093121.655728");
        assert!(result.is_ok());
        let ts = result.unwrap();
        assert_eq!(ts.as_second(), 1_562_093_121);
        assert_eq!(ts.subsec_microsecond(), 655_728);
    }

    #[test]
    fn test_parse_zeek_timestamp_zero_microseconds() {
        // Timestamp with zero microseconds
        let result = parse_zeek_timestamp("1562093121.000000");
        assert!(result.is_ok());
        let ts = result.unwrap();
        assert_eq!(ts.as_second(), 1_562_093_121);
        assert_eq!(ts.subsec_microsecond(), 0);
    }

    #[test]
    fn test_parse_zeek_timestamp_one_microsecond() {
        // Timestamp with one microsecond
        let result = parse_zeek_timestamp("1562093121.000001");
        assert!(result.is_ok());
        let ts = result.unwrap();
        assert_eq!(ts.subsec_microsecond(), 1);
    }

    #[test]
    fn test_parse_zeek_timestamp_max_microseconds() {
        // Maximum microseconds (999999)
        let result = parse_zeek_timestamp("1562093121.999999");
        assert!(result.is_ok());
        let ts = result.unwrap();
        assert_eq!(ts.subsec_microsecond(), 999_999);
    }

    #[test]
    fn test_parse_zeek_timestamp_epoch() {
        // Unix epoch
        let result = parse_zeek_timestamp("0.000000");
        assert!(result.is_ok());
        let ts = result.unwrap();
        assert_eq!(ts.as_second(), 0);
    }

    #[test]
    fn test_parse_zeek_timestamp_missing_dot() {
        // Invalid: no decimal point
        let result = parse_zeek_timestamp("1562093121");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_zeek_timestamp_invalid_seconds() {
        // Invalid: non-numeric seconds
        let result = parse_zeek_timestamp("invalid.123456");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_zeek_timestamp_invalid_microseconds() {
        // Invalid: non-numeric microseconds
        let result = parse_zeek_timestamp("1562093121.abc");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_zeek_timestamp_empty_string() {
        // Invalid: empty string
        let result = parse_zeek_timestamp("");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_zeek_timestamp_overflow_microseconds() {
        // Microseconds > 999999 will cause overflow when converted to nanoseconds
        // This tests that very large microsecond values are handled
        let result = parse_zeek_timestamp("1562093121.1000000");
        // This will parse the microseconds as i32, but may fail in timestamp creation
        // depending on the overflow behavior
        let _ = result; // Just verify it doesn't panic
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_zeek_timestamp_year_2000() {
        // Y2K timestamp: 2000-01-01 00:00:00 UTC
        let result = parse_zeek_timestamp("946684800.000000");
        assert!(result.is_ok());
        let ts = result.unwrap();
        assert_eq!(ts.as_second(), 946_684_800);
    }

    #[test]
    fn test_parse_zeek_timestamp_year_2038() {
        // Near 32-bit Unix timestamp limit: 2038-01-19 03:14:07 UTC
        let result = parse_zeek_timestamp("2147483647.999999");
        assert!(result.is_ok());
        let ts = result.unwrap();
        assert_eq!(ts.as_second(), 2_147_483_647);
    }

    #[test]
    fn test_parse_zeek_timestamp_conversion_to_nanos() {
        // Verify nanosecond conversion
        let result = parse_zeek_timestamp("1562093121.655728");
        assert!(result.is_ok());
        let ts = result.unwrap();
        let nanos = i64::try_from(ts.as_nanosecond());
        assert!(nanos.is_ok());
        // 1562093121 seconds * 1_000_000_000 + 655728 microseconds * 1000
        assert_eq!(nanos.unwrap(), 1_562_093_121_655_728_000);
    }

    #[test]
    fn test_parse_zeek_timestamp_ns_returns_nanoseconds() {
        let ns = parse_zeek_timestamp_ns("1700000000.765432").unwrap();
        assert_eq!(ns, 1_700_000_000_765_432_000);
    }
}
