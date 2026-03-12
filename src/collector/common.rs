/// Applies timestamp deduplication by incrementing the offset for consecutive
/// identical timestamps.
///
/// Returns the deduplicated timestamp (original + offset). When a new
/// timestamp is encountered the reference is updated and the offset resets to
/// 0. For identical consecutive timestamps the offset increments by 1 for
/// each occurrence.
pub(crate) fn apply_timestamp_dedup(
    current_timestamp: i64,
    reference_timestamp: &mut Option<i64>,
    timestamp_offset: &mut i64,
) -> i64 {
    if let Some(ref_ts) = *reference_timestamp {
        if current_timestamp == ref_ts {
            *timestamp_offset += 1;
        } else {
            *reference_timestamp = Some(current_timestamp);
            *timestamp_offset = 0;
        }
    } else {
        *reference_timestamp = Some(current_timestamp);
    }
    current_timestamp + *timestamp_offset
}

#[cfg(test)]
mod tests {
    use super::apply_timestamp_dedup;

    #[test]
    fn dedup_resets_offset_on_new_timestamp() {
        let mut ref_ts: Option<i64> = None;
        let mut offset = 0_i64;

        assert_eq!(apply_timestamp_dedup(100, &mut ref_ts, &mut offset), 100);
        assert_eq!(apply_timestamp_dedup(100, &mut ref_ts, &mut offset), 101);
        assert_eq!(apply_timestamp_dedup(200, &mut ref_ts, &mut offset), 200);
        assert_eq!(apply_timestamp_dedup(200, &mut ref_ts, &mut offset), 201);
        assert_eq!(apply_timestamp_dedup(200, &mut ref_ts, &mut offset), 202);
    }

    #[test]
    fn dedup_no_offset_for_distinct_timestamps() {
        let mut ref_ts: Option<i64> = None;
        let mut offset = 0_i64;

        assert_eq!(apply_timestamp_dedup(100, &mut ref_ts, &mut offset), 100);
        assert_eq!(apply_timestamp_dedup(200, &mut ref_ts, &mut offset), 200);
        assert_eq!(apply_timestamp_dedup(300, &mut ref_ts, &mut offset), 300);
    }

    #[test]
    fn dedup_single_event() {
        let mut ref_ts: Option<i64> = None;
        let mut offset = 0_i64;

        assert_eq!(apply_timestamp_dedup(42, &mut ref_ts, &mut offset), 42);
        assert_eq!(ref_ts, Some(42));
        assert_eq!(offset, 0);
    }
}
