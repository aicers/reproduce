mod network;
mod sysmon;
#[cfg(test)]
mod tests;

use std::str::FromStr;

use anyhow::{Context, Result, anyhow};
use csv::StringRecord;
use jiff::Timestamp;

pub(crate) trait TryFromGigantoRecord: Sized {
    fn try_from_giganto_record(rec: &StringRecord) -> Result<(Self, i64)>;
}

fn parse_giganto_timestamp(timestamp: &str) -> Result<Timestamp> {
    if let Some(i) = timestamp.find('.') {
        let secs = timestamp[..i].parse::<i64>().context("invalid timestamp")?;
        let nanos = timestamp[i + 1..]
            .parse::<i32>()
            .context("invalid timestamp")?;
        Timestamp::new(secs, nanos).map_err(|e| anyhow!("failed to create Timestamp: {e}"))
    } else {
        Err(anyhow!("invalid timestamp: {timestamp}"))
    }
}

fn parse_giganto_timestamp_ns(timestamp: &str) -> Result<i64> {
    let ts = parse_giganto_timestamp(timestamp)?;
    i64::try_from(ts.as_nanosecond()).context("to_timestamp_nanos")
}

fn parse_comma_separated<T: FromStr>(s: &str) -> std::result::Result<Vec<T>, T::Err> {
    let mut v = Vec::new();
    if s != "-" {
        for t in s.split(',') {
            v.push(t.parse()?);
        }
    }
    Ok(v)
}

fn parse_post_body(s: &str) -> Vec<u8> {
    if s != "-" && !s.is_empty() {
        s.as_bytes().to_vec()
    } else {
        Vec::new()
    }
}
#[cfg(test)]
mod giganto_timestamp_tests {
    use super::*;

    #[test]
    fn parse_giganto_timestamp_valid() {
        // 2019-07-02 20:45:21.655728123 UTC
        let ts = parse_giganto_timestamp("1562093121.655728123").unwrap();
        assert_eq!(ts.as_second(), 1_562_093_121);
        assert_eq!(ts.subsec_nanosecond(), 655_728_123);
    }

    #[test]
    fn parse_giganto_timestamp_zero_nanos() {
        let ts = parse_giganto_timestamp("1562093121.000000000").unwrap();
        assert_eq!(ts.as_second(), 1_562_093_121);
        assert_eq!(ts.subsec_nanosecond(), 0);
    }

    #[test]
    fn parse_giganto_timestamp_one_nanosecond() {
        let ts = parse_giganto_timestamp("1562093121.000000001").unwrap();
        assert_eq!(ts.subsec_nanosecond(), 1);
    }

    #[test]
    fn parse_giganto_timestamp_max_nanoseconds() {
        let ts = parse_giganto_timestamp("1562093121.999999999").unwrap();
        assert_eq!(ts.subsec_nanosecond(), 999_999_999);
    }

    #[test]
    fn parse_giganto_timestamp_epoch() {
        let ts = parse_giganto_timestamp("0.000000000").unwrap();
        assert_eq!(ts.as_second(), 0);
        assert_eq!(ts.subsec_nanosecond(), 0);
    }

    #[test]
    fn parse_giganto_timestamp_missing_dot() {
        assert!(parse_giganto_timestamp("1562093121").is_err());
    }

    #[test]
    fn parse_giganto_timestamp_invalid_seconds() {
        assert!(parse_giganto_timestamp("invalid.123456789").is_err());
    }

    #[test]
    fn parse_giganto_timestamp_invalid_nanos() {
        assert!(parse_giganto_timestamp("1562093121.abc").is_err());
    }

    #[test]
    fn parse_giganto_timestamp_empty_string() {
        assert!(parse_giganto_timestamp("").is_err());
    }

    #[test]
    fn parse_giganto_timestamp_overflow_nanoseconds() {
        // 10-digit nanos should be rejected by Timestamp::new
        assert!(parse_giganto_timestamp("1562093121.1000000000").is_err());
    }

    #[test]
    fn parse_giganto_timestamp_year_2000() {
        let ts = parse_giganto_timestamp("946684800.000000000").unwrap();
        assert_eq!(ts.as_second(), 946_684_800);
    }

    #[test]
    fn parse_giganto_timestamp_year_2038() {
        let ts = parse_giganto_timestamp("2147483647.999999999").unwrap();
        assert_eq!(ts.as_second(), 2_147_483_647);
        assert_eq!(ts.subsec_nanosecond(), 999_999_999);
    }

    #[test]
    fn parse_giganto_timestamp_conversion_to_nanos() {
        let ts = parse_giganto_timestamp("1562093121.655728123").unwrap();
        let nanos = i64::try_from(ts.as_nanosecond()).unwrap();
        assert_eq!(nanos, 1_562_093_121_655_728_123);
    }

    #[test]
    fn parse_giganto_timestamp_ns_returns_nanoseconds() {
        let ns = parse_giganto_timestamp_ns("1700000000.765432111").unwrap();
        assert_eq!(ns, 1_700_000_000_765_432_111);
    }

    #[test]
    fn parse_giganto_timestamp_negative() {
        // Large negative seconds with positive subseconds (before Unix epoch)
        // Input: -1000000 seconds + 500000000 nanoseconds = -999999.5 seconds total
        // jiff represents this with truncation toward zero:
        //   as_second() = -999999 (truncated toward zero)
        //   subsec_nanosecond() = -500000000 (remainder, preserving sign)
        let ts = parse_giganto_timestamp("-1000000.500000000").unwrap();
        assert_eq!(ts.as_second(), -999_999);
        assert_eq!(ts.subsec_nanosecond(), -500_000_000);
    }

    #[test]
    fn parse_giganto_timestamp_negative_one_second() {
        // Negative one second with small nanos
        // Input: -1 seconds + 1 nanosecond = -0.999999999 seconds total
        // jiff represents this with truncation toward zero:
        //   as_second() = 0 (truncated toward zero)
        //   subsec_nanosecond() = -999999999 (remainder, preserving sign)
        let ts = parse_giganto_timestamp("-1.000000001").unwrap();
        assert_eq!(ts.as_second(), 0);
        assert_eq!(ts.subsec_nanosecond(), -999_999_999);
    }

    #[test]
    fn parse_giganto_timestamp_negative_fractional() {
        // Small negative fraction less than 1 second
        // Note: "-0" parses as 0, so this represents a positive timestamp (0.5 seconds)
        let ts = parse_giganto_timestamp("-0.500000000").unwrap();
        assert_eq!(ts.as_second(), 0);
        assert_eq!(ts.subsec_nanosecond(), 500_000_000);
    }

    #[test]
    fn parse_giganto_timestamp_negative_ns_conversion() {
        // Verify nanosecond conversion for negative timestamps
        // Total: -1000000 * 1e9 + 500000000 = -999999500000000 nanoseconds
        let ns = parse_giganto_timestamp_ns("-1000000.500000000").unwrap();
        assert_eq!(ns, -999_999_500_000_000);
    }
}
