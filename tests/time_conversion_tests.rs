// Comprehensive tests for Chrono-based time conversion logic
// These tests verify the current behavior before migration to Jiff

use chrono::{DateTime, FixedOffset, NaiveDateTime, TimeZone, Utc};

/// Test `parse_giganto_timestamp` functionality from migration.rs
mod giganto_timestamp {
    use anyhow::{Context, Result, anyhow};

    use super::*;

    fn parse_giganto_timestamp(timestamp: &str) -> Result<DateTime<Utc>> {
        if let Some(i) = timestamp.find('.') {
            let secs = timestamp[..i].parse::<i64>().context("invalid timestamp")?;
            let micros = timestamp[i + 1..]
                .parse::<u32>()
                .context("invalid timestamp")?;
            // Note: In the original code, micros is passed as-is (to nanoseconds parameter)
            // This is a bug that will be fixed during Jiff migration
            let Some(time) = DateTime::from_timestamp(secs, micros) else {
                return Err(anyhow!("failed to create DateTime<Utc> from timestamp"));
            };
            Ok(time)
        } else {
            Err(anyhow!("invalid timestamp: {timestamp}"))
        }
    }

    #[test]
    fn test_basic_timestamp_parsing() {
        let timestamp = "1562093121.655728";
        let result = parse_giganto_timestamp(timestamp);
        assert!(result.is_ok());

        let datetime = result.unwrap();
        assert_eq!(datetime.timestamp(), 1_562_093_121);
        // Bug in original: micros treated as nanos, so 655728 nanos = 655 micros
        assert_eq!(datetime.timestamp_subsec_micros(), 655);
    }

    #[test]
    fn test_timestamp_with_zero_microseconds() {
        let timestamp = "1562093121.0";
        let result = parse_giganto_timestamp(timestamp);
        assert!(result.is_ok());

        let datetime = result.unwrap();
        assert_eq!(datetime.timestamp(), 1_562_093_121);
        assert_eq!(datetime.timestamp_subsec_micros(), 0);
    }

    #[test]
    fn test_timestamp_with_large_microseconds() {
        let timestamp = "1562093121.999999";
        let result = parse_giganto_timestamp(timestamp);
        assert!(result.is_ok());

        let datetime = result.unwrap();
        assert_eq!(datetime.timestamp(), 1_562_093_121);
        // Bug in original: micros treated as nanos, so 999999 nanos = 999 micros
        assert_eq!(datetime.timestamp_subsec_micros(), 999);
    }

    #[test]
    fn test_negative_timestamp() {
        let timestamp = "-1.0";
        let result = parse_giganto_timestamp(timestamp);
        assert!(result.is_ok());

        let datetime = result.unwrap();
        assert_eq!(datetime.timestamp(), -1);
    }

    #[test]
    fn test_invalid_timestamp_no_decimal() {
        let timestamp = "1562093121";
        let result = parse_giganto_timestamp(timestamp);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_timestamp_format() {
        let timestamp = "not_a_timestamp.123";
        let result = parse_giganto_timestamp(timestamp);
        assert!(result.is_err());
    }

    #[test]
    fn test_timestamp_to_nanoseconds_conversion() {
        let timestamp = "1562093121.655728";
        let datetime = parse_giganto_timestamp(timestamp).unwrap();
        let nanos = datetime.timestamp_nanos_opt();
        assert!(nanos.is_some());

        // Bug in original: micros treated as nanos
        let nanos = nanos.unwrap();
        assert_eq!(nanos, 1_562_093_121_000_655_728);
    }
}

/// Test `parse_zeek_timestamp` functionality from zeek.rs
mod zeek_timestamp {
    use anyhow::{Context, Result, anyhow};

    use super::*;

    fn parse_zeek_timestamp(timestamp: &str) -> Result<DateTime<Utc>> {
        if let Some(i) = timestamp.find('.') {
            let secs = timestamp[..i].parse::<i64>().context("invalid timestamp")?;
            let micros = timestamp[i + 1..]
                .parse::<u32>()
                .context("invalid timestamp")?;
            let Some(time) = DateTime::from_timestamp(secs, micros * 1000) else {
                return Err(anyhow!("failed to create DatTime<Utc> from timestamp"));
            };
            Ok(time)
        } else {
            Err(anyhow!("invalid timestamp: {timestamp}"))
        }
    }

    #[test]
    fn test_basic_zeek_timestamp() {
        let timestamp = "1562093121.655728";
        let result = parse_zeek_timestamp(timestamp);
        assert!(result.is_ok());

        let datetime = result.unwrap();
        assert_eq!(datetime.timestamp(), 1_562_093_121);
        assert_eq!(datetime.timestamp_subsec_micros(), 655_728);
    }

    #[test]
    fn test_zeek_timestamp_microsecond_conversion() {
        // Zeek multiplies by 1000 to convert from microseconds to nanoseconds
        let timestamp = "1562093121.123456";
        let datetime = parse_zeek_timestamp(timestamp).unwrap();

        // Verify the subsecond part is correct
        assert_eq!(datetime.timestamp_subsec_nanos(), 123_456_000);
    }

    #[test]
    fn test_zeek_timestamp_to_nanos() {
        let timestamp = "1562093121.655728";
        let datetime = parse_zeek_timestamp(timestamp).unwrap();
        let nanos = datetime.timestamp_nanos_opt();
        assert!(nanos.is_some());
        assert_eq!(nanos.unwrap(), 1_562_093_121_655_728_000);
    }

    #[test]
    fn test_zeek_timestamp_zero_subseconds() {
        let timestamp = "1562093121.0";
        let result = parse_zeek_timestamp(timestamp);
        assert!(result.is_ok());

        let datetime = result.unwrap();
        assert_eq!(datetime.timestamp_subsec_nanos(), 0);
    }
}

/// Test `parse_sysmon_time` functionality from syslog.rs
mod sysmon_time {
    use anyhow::{Result, anyhow};

    use super::*;

    fn parse_sysmon_time(time: &str) -> Result<DateTime<Utc>> {
        if let Ok(ndt) = NaiveDateTime::parse_from_str(time, "%Y-%m-%d %H:%M:%S%.f") {
            Ok(DateTime::<Utc>::from_naive_utc_and_offset(ndt, Utc))
        } else {
            Err(anyhow!("invalid time: {time}"))
        }
    }

    #[test]
    fn test_basic_sysmon_time() {
        let time = "2023-01-02 07:36:17.123456";
        let result = parse_sysmon_time(time);
        assert!(result.is_ok());

        let datetime = result.unwrap();
        // Timezone interpretation difference - this is in local time zone
        assert_eq!(datetime.timestamp(), 1_672_644_977);
        assert_eq!(datetime.timestamp_subsec_micros(), 123_456);
    }

    #[test]
    fn test_sysmon_time_no_subseconds() {
        let time = "2023-01-02 07:36:17";
        let result = parse_sysmon_time(time);
        assert!(result.is_ok());

        let datetime = result.unwrap();
        assert_eq!(datetime.timestamp_subsec_nanos(), 0);
    }

    #[test]
    fn test_sysmon_time_with_full_precision() {
        let time = "2023-01-02 07:36:17.999999999";
        let result = parse_sysmon_time(time);
        assert!(result.is_ok());

        let datetime = result.unwrap();
        assert_eq!(datetime.timestamp_subsec_nanos(), 999_999_999);
    }

    #[test]
    fn test_sysmon_time_to_nanos() {
        let time = "2023-01-02 07:36:17.123456";
        let datetime = parse_sysmon_time(time).unwrap();
        let nanos = datetime.timestamp_nanos_opt();
        assert!(nanos.is_some());
    }

    #[test]
    fn test_invalid_sysmon_time_format() {
        let time = "not_a_valid_time";
        let result = parse_sysmon_time(time);
        assert!(result.is_err());
    }
}

/// Test `parse_srx_timestamp` functionality from `security_log/srx.rs`
mod srx_timestamp {
    use anyhow::{Result, anyhow};

    use super::*;

    fn parse_srx_timestamp(datetime: &str) -> Result<DateTime<FixedOffset>> {
        DateTime::parse_from_str(datetime, "%Y-%m-%dT%H:%M:%S%.f%z").map_err(|e| anyhow!("{e:?}"))
    }

    #[test]
    fn test_basic_srx_timestamp() {
        let datetime = "2023-01-02T07:36:17.123+09:00";
        let result = parse_srx_timestamp(datetime);
        assert!(result.is_ok());

        let dt = result.unwrap();
        // 2023-01-02 07:36:17 in +09:00 = 2023-01-01 22:36:17 UTC
        assert_eq!(dt.timestamp(), 1_672_612_577);
        assert_eq!(dt.offset().local_minus_utc(), 9 * 3600);
    }

    #[test]
    fn test_srx_timestamp_negative_offset() {
        let datetime = "2023-01-02T07:36:17.123-05:00";
        let result = parse_srx_timestamp(datetime);
        assert!(result.is_ok());

        let dt = result.unwrap();
        assert_eq!(dt.offset().local_minus_utc(), -5 * 3600);
    }

    #[test]
    fn test_srx_timestamp_to_nanos() {
        let datetime = "2023-01-02T07:36:17.123456+09:00";
        let dt = parse_srx_timestamp(datetime).unwrap();
        let nanos = dt.timestamp_nanos_opt();
        assert!(nanos.is_some());
    }

    #[test]
    fn test_srx_timestamp_utc() {
        let datetime = "2023-01-02T07:36:17.123+00:00";
        let result = parse_srx_timestamp(datetime);
        assert!(result.is_ok());

        let dt = result.unwrap();
        assert_eq!(dt.offset().local_minus_utc(), 0);
    }

    #[test]
    fn test_invalid_srx_timestamp() {
        let datetime = "not_a_timestamp";
        let result = parse_srx_timestamp(datetime);
        assert!(result.is_err());
    }
}

/// Test `parse_oplog_timestamp` functionality from `operation_log.rs`
mod oplog_timestamp {
    use std::str::FromStr;

    use anyhow::{Result, anyhow};

    use super::*;

    fn parse_oplog_timestamp(datetime: &str) -> Result<DateTime<Utc>> {
        DateTime::from_str(datetime).map_err(|e| anyhow!("{e:?}"))
    }

    #[test]
    fn test_basic_oplog_timestamp() {
        let datetime = "2023-01-02T07:36:17Z";
        let result = parse_oplog_timestamp(datetime);
        assert!(result.is_ok());

        let dt = result.unwrap();
        assert_eq!(dt.timestamp(), 1_672_644_977);
    }

    #[test]
    fn test_oplog_timestamp_with_subseconds() {
        let datetime = "2023-01-02T07:36:17.123123Z";
        let result = parse_oplog_timestamp(datetime);
        assert!(result.is_ok());

        let dt = result.unwrap();
        assert_eq!(dt.timestamp(), 1_672_644_977);
        assert_eq!(dt.timestamp_subsec_micros(), 123_123);
    }

    #[test]
    fn test_oplog_timestamp_to_nanos() {
        let datetime = "2023-01-02T07:36:17.789789Z";
        let dt = parse_oplog_timestamp(datetime).unwrap();
        let nanos = dt.timestamp_nanos_opt();
        assert!(nanos.is_some());

        let expected_nanos = Utc
            .with_ymd_and_hms(2023, 1, 2, 7, 36, 17)
            .unwrap()
            .timestamp_nanos_opt()
            .unwrap()
            + 789_789_000;
        assert_eq!(nanos.unwrap(), expected_nanos);
    }

    #[test]
    fn test_invalid_oplog_timestamp() {
        let datetime = "not_a_timestamp";
        let result = parse_oplog_timestamp(datetime);
        assert!(result.is_err());
    }
}

/// Test `Utc::now()` usage from producer.rs
mod current_time {
    use super::*;

    #[test]
    fn test_utc_now_to_nanos() {
        let now = Utc::now();
        let nanos = now.timestamp_nanos_opt();
        assert!(nanos.is_some());

        // Verify the nanoseconds are reasonable (positive and recent)
        let nanos_value = nanos.unwrap();
        assert!(nanos_value > 0);
    }

    #[test]
    fn test_utc_now_timestamp() {
        let now = Utc::now();
        let timestamp = now.timestamp();

        // Should be a recent timestamp (after 2020)
        assert!(timestamp > 1_577_836_800); // 2020-01-01
    }
}

/// Test `DateTime` construction and conversion patterns
mod datetime_construction {
    use super::*;

    #[test]
    fn test_from_timestamp_basic() {
        let dt = DateTime::from_timestamp(1_562_093_121, 655_728_000);
        assert!(dt.is_some());

        let dt = dt.unwrap();
        assert_eq!(dt.timestamp(), 1_562_093_121);
        assert_eq!(dt.timestamp_subsec_nanos(), 655_728_000);
    }

    #[test]
    fn test_from_timestamp_zero() {
        let dt = DateTime::from_timestamp(0, 0);
        assert!(dt.is_some());

        let dt = dt.unwrap();
        assert_eq!(dt.timestamp(), 0);
    }

    #[test]
    fn test_from_timestamp_negative() {
        let dt = DateTime::from_timestamp(-1, 0);
        assert!(dt.is_some());

        let dt = dt.unwrap();
        assert_eq!(dt.timestamp(), -1);
    }

    #[test]
    fn test_timestamp_nanos_opt_boundary() {
        // Test a timestamp that should work
        let dt = DateTime::from_timestamp(1_000_000_000, 0).unwrap();
        let nanos = dt.timestamp_nanos_opt();
        assert!(nanos.is_some());
        assert_eq!(nanos.unwrap(), 1_000_000_000_000_000_000);
    }

    #[test]
    fn test_from_naive_utc_and_offset() {
        let naive =
            NaiveDateTime::parse_from_str("2023-01-02 07:36:17", "%Y-%m-%d %H:%M:%S").unwrap();
        let dt = DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc);

        assert_eq!(dt.timestamp(), 1_672_644_977);
    }
}

/// Test timestamp arithmetic and offset handling
mod timestamp_arithmetic {

    #[test]
    fn test_timestamp_with_serial_offset() {
        // Simulating the serial offset logic from security logs
        let base_nanos = 1_562_093_121_655_728_000_i64;
        let serial = 123_i64;
        let final_timestamp = base_nanos + serial;

        assert_eq!(final_timestamp, 1_562_093_121_655_728_123);
    }

    #[test]
    fn test_timestamp_offset_deduplication() {
        // Simulating the deduplication logic from producer.rs
        let timestamp1 = 1_562_093_121_655_728_000_i64;
        let timestamp2 = 1_562_093_121_655_728_000_i64; // Same timestamp
        let offset = 1_i64;

        let adjusted = timestamp2 + offset;
        assert_eq!(adjusted, timestamp1 + 1);
    }
}

/// Test edge cases and boundary conditions
mod edge_cases {
    use anyhow::{Context, Result, anyhow};
    use chrono::{DateTime, Utc};

    fn parse_giganto_timestamp(timestamp: &str) -> Result<DateTime<Utc>> {
        if let Some(i) = timestamp.find('.') {
            let secs = timestamp[..i].parse::<i64>().context("invalid timestamp")?;
            let micros = timestamp[i + 1..]
                .parse::<u32>()
                .context("invalid timestamp")?;
            // Note: Bug in original - micros treated as nanos
            let Some(time) = DateTime::from_timestamp(secs, micros) else {
                return Err(anyhow!("failed to create DateTime<Utc> from timestamp"));
            };
            Ok(time)
        } else {
            Err(anyhow!("invalid timestamp: {timestamp}"))
        }
    }

    #[test]
    fn test_minimum_valid_timestamp() {
        let dt = DateTime::from_timestamp(0, 0);
        assert!(dt.is_some());
    }

    #[test]
    fn test_maximum_nanoseconds() {
        let dt = DateTime::from_timestamp(1_000_000, 999_999_999);
        assert!(dt.is_some());

        let dt = dt.unwrap();
        assert_eq!(dt.timestamp_subsec_nanos(), 999_999_999);
    }

    #[test]
    fn test_timestamp_with_leading_zeros() {
        let timestamp = "1562093121.000001";
        let result = parse_giganto_timestamp(timestamp);
        assert!(result.is_ok());

        let datetime = result.unwrap();
        // Bug in original: 1 nano = 0 micros (rounded down)
        assert_eq!(datetime.timestamp_subsec_micros(), 0);
    }
}
