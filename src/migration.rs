mod network;
#[cfg(test)]
mod tests;

use std::str::FromStr;

use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, Utc};
use csv::StringRecord;

pub(crate) trait TryFromGigantoRecord: Sized {
    fn try_from_giganto_record(rec: &StringRecord) -> Result<(Self, i64)>;
}

fn parse_giganto_timestamp(timestamp: &str) -> Result<DateTime<Utc>> {
    if let Some(i) = timestamp.find('.') {
        let secs = timestamp[..i].parse::<i64>().context("invalid timestamp")?;
        let micros = timestamp[i + 1..]
            .parse::<u32>()
            .context("invalid timestamp")?;
        let Some(time) = DateTime::from_timestamp(secs, micros) else {
            return Err(anyhow!("failed to create DateTime<Utc> from timestamp"));
        };
        Ok(time)
    } else {
        Err(anyhow!("invalid timestamp: {timestamp}"))
    }
}

fn parse_giganto_timestamp_ns(timestamp: &str) -> Result<i64> {
    parse_giganto_timestamp(timestamp)?
        .timestamp_nanos_opt()
        .context("to_timestamp_nanos")
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
        assert_eq!(ts.timestamp(), 1_562_093_121);
        assert_eq!(ts.timestamp_subsec_nanos(), 655_728_123);
    }

    #[test]
    fn parse_giganto_timestamp_zero_nanos() {
        let ts = parse_giganto_timestamp("1562093121.000000000").unwrap();
        assert_eq!(ts.timestamp(), 1_562_093_121);
        assert_eq!(ts.timestamp_subsec_nanos(), 0);
    }

    #[test]
    fn parse_giganto_timestamp_one_nanosecond() {
        let ts = parse_giganto_timestamp("1562093121.000000001").unwrap();
        assert_eq!(ts.timestamp_subsec_nanos(), 1);
    }

    #[test]
    fn parse_giganto_timestamp_max_nanoseconds() {
        let ts = parse_giganto_timestamp("1562093121.999999999").unwrap();
        assert_eq!(ts.timestamp_subsec_nanos(), 999_999_999);
    }

    #[test]
    fn parse_giganto_timestamp_epoch() {
        let ts = parse_giganto_timestamp("0.000000000").unwrap();
        assert_eq!(ts.timestamp(), 0);
        assert_eq!(ts.timestamp_subsec_nanos(), 0);
    }

    #[test]
    fn parse_giganto_timestamp_negative() {
        let ts = parse_giganto_timestamp("-1000000.500000000").unwrap();
        assert_eq!(ts.timestamp(), -1_000_000);
        assert_eq!(ts.timestamp_subsec_nanos(), 500_000_000);
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
        // 10-digit nanos should be rejected by DateTime::from_timestamp
        assert!(parse_giganto_timestamp("1562093121.1000000000").is_err());
    }

    #[test]
    fn parse_giganto_timestamp_year_2000() {
        let ts = parse_giganto_timestamp("946684800.000000000").unwrap();
        assert_eq!(ts.timestamp(), 946_684_800);
    }

    #[test]
    fn parse_giganto_timestamp_year_2038() {
        let ts = parse_giganto_timestamp("2147483647.999999999").unwrap();
        assert_eq!(ts.timestamp(), 2_147_483_647);
        assert_eq!(ts.timestamp_subsec_nanos(), 999_999_999);
    }

    #[test]
    fn parse_giganto_timestamp_conversion_to_nanos() {
        let ts = parse_giganto_timestamp("1562093121.655728123").unwrap();
        let nanos = ts.timestamp_nanos_opt().unwrap();
        assert_eq!(nanos, 1_562_093_121_655_728_123);
    }

    #[test]
    fn parse_giganto_timestamp_ns_returns_nanoseconds() {
        let ns = parse_giganto_timestamp_ns("1700000000.765432111").unwrap();
        assert_eq!(ns, 1_700_000_000_765_432_111);
    }
}
