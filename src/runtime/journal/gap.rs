//! The lost-interval check of the journal collector's reader.
//!
//! Sequence numbers count every journal entry, kept or not, so an entry
//! whose `__SEQNUM` is more than one past its predecessor's, besides the
//! over-long lines skipped between them, or whose `__SEQNUM_ID` differs,
//! follows entries that were removed before they were read, or that
//! journald lost.

use tracing::{info, warn};

use super::JournalPosition;

/// The warnings of the lost-interval check, and what keeps them from
/// repeating.
#[derive(Debug, Default)]
pub(super) struct Gaps {
    /// The cursors of the two entries of the last warning.
    warned: Option<(String, String)>,
    /// Whether the line about unavailable sequence numbers was logged since
    /// the last comparison made.
    unavailable: bool,
}

impl Gaps {
    /// Compares `entry` with its predecessor `previous`, with `skipped`
    /// over-long lines skipped between them, and logs a warning when entries
    /// between them may be missing, once for the same two entries.
    pub(super) fn check(
        &mut self,
        previous: &JournalPosition,
        entry: &JournalPosition,
        skipped: u64,
    ) {
        let Some(gap) = gap(previous, entry, skipped) else {
            if !self.unavailable {
                info!(
                    "journal sequence numbers are unavailable; the lost-interval check is skipped"
                );
                self.unavailable = true;
            }
            return;
        };
        self.unavailable = false;
        if !gap {
            return;
        }
        let pair = (previous.cursor.clone(), entry.cursor.clone());
        if self.warned.as_ref() == Some(&pair) {
            return;
        }
        warn!(
            "journal entries between {} and {} may be missing: removed before they were sent, \
             or lost by journald",
            time(previous.realtime_us),
            time(entry.realtime_us)
        );
        self.warned = Some(pair);
    }
}

/// Tells whether entries may be missing between `a` and the entry `b` after
/// it, `skipped` over-long lines being skipped between them; `None` if
/// either lacks a sequence number or its ID.
fn gap(a: &JournalPosition, b: &JournalPosition, skipped: u64) -> Option<bool> {
    let (a_id, a_seqnum) = (a.seqnum_id.as_ref()?, a.seqnum?);
    let (b_id, b_seqnum) = (b.seqnum_id.as_ref()?, b.seqnum?);
    Some(a_id != b_id || b_seqnum > a_seqnum.saturating_add(1).saturating_add(skipped))
}

/// Formats an entry's `__REALTIME_TIMESTAMP` as an RFC 3339 UTC timestamp
/// with microseconds.
fn time(realtime_us: Option<u64>) -> String {
    realtime_us
        .and_then(|us| i64::try_from(us).ok())
        .and_then(|us| jiff::Timestamp::from_microsecond(us).ok())
        .map_or_else(
            || "an unknown time".to_string(),
            |time| format!("{time:.6}"),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn position(cursor: &str, seqnum_id: Option<&str>, seqnum: Option<u64>) -> JournalPosition {
        JournalPosition {
            cursor: cursor.to_string(),
            seqnum_id: seqnum_id.map(str::to_string),
            seqnum,
            realtime_us: Some(1_792_638_245_123_456),
        }
    }

    #[test]
    fn gaps_follow_sequence_numbers_and_skipped_lines() {
        let a = position("a", Some("x"), Some(10));
        assert_eq!(gap(&a, &position("b", Some("x"), Some(11)), 0), Some(false));
        assert_eq!(gap(&a, &position("b", Some("x"), Some(12)), 0), Some(true));
        // Skipped over-long lines are counted.
        assert_eq!(gap(&a, &position("b", Some("x"), Some(12)), 1), Some(false));
        assert_eq!(gap(&a, &position("b", Some("x"), Some(14)), 2), Some(true));
        // A sequence number that does not move forward is no gap.
        assert_eq!(gap(&a, &position("b", Some("x"), Some(10)), 0), Some(false));
        assert_eq!(gap(&a, &position("b", Some("x"), Some(3)), 0), Some(false));
        // A new sequence number ID.
        assert_eq!(gap(&a, &position("b", Some("y"), Some(11)), 0), Some(true));
        // Missing sequence numbers.
        assert_eq!(gap(&a, &position("b", None, Some(11)), 0), None);
        assert_eq!(gap(&a, &position("b", Some("x"), None), 0), None);
        assert_eq!(gap(&position("a", Some("x"), None), &a, 0), None);
        // No overflow.
        let max = position("a", Some("x"), Some(u64::MAX));
        assert_eq!(
            gap(&max, &position("b", Some("x"), Some(u64::MAX)), u64::MAX),
            Some(false)
        );
        assert_eq!(
            gap(&position("a", Some("x"), Some(u64::MAX - 1)), &max, 0),
            Some(false)
        );
    }

    #[test]
    fn times_have_six_fractional_digits() {
        assert_eq!(
            time(Some(1_792_638_245_123_456)),
            "2026-10-22T03:04:05.123456Z"
        );
        assert_eq!(
            time(Some(1_792_638_245_000_000)),
            "2026-10-22T03:04:05.000000Z"
        );
        assert_eq!(time(Some(0)), "1970-01-01T00:00:00.000000Z");
        assert_eq!(time(None), "an unknown time");
        // Past what `jiff::Timestamp` represents.
        assert_eq!(time(Some(300_000_000_000_000_000)), "an unknown time");
        assert_eq!(time(Some(u64::MAX)), "an unknown time");
    }
}
