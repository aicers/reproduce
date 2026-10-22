//! The rate limits of the journal collector's warnings.
//!
//! Each limit takes the current instant as an argument, so it is tested with
//! constructed instants.

use std::time::{Duration, Instant};

/// Lets one event through per interval: the first at once, and later ones
/// only once the interval has passed since the last one let through.
#[derive(Debug)]
pub(super) struct Every {
    interval: Duration,
    last: Option<Instant>,
}

impl Every {
    pub(super) fn new(interval: Duration) -> Self {
        Self {
            interval,
            last: None,
        }
    }

    /// Tells whether an event at `now` is let through.
    pub(super) fn ready(&mut self, now: Instant) -> bool {
        if self
            .last
            .is_some_and(|last| now.saturating_duration_since(last) < self.interval)
        {
            return false;
        }
        self.last = Some(now);
        true
    }
}

/// Counts events and reports them at most once per interval: the first at
/// once, and later ones with how many happened since the last report.
#[derive(Debug)]
pub(super) struct Counted {
    every: Every,
    count: u64,
}

impl Counted {
    pub(super) fn new(interval: Duration) -> Self {
        Self {
            every: Every::new(interval),
            count: 0,
        }
    }

    /// Counts an event at `now`. Returns how many events to report, this
    /// one included, if a report is due.
    pub(super) fn count(&mut self, now: Instant) -> Option<u64> {
        self.count += 1;
        if !self.every.ready(now) {
            return None;
        }
        Some(std::mem::take(&mut self.count))
    }
}

/// Lets a cause through at once when it differs from the previous one, and
/// the same cause again only once the interval has passed since it was last
/// let through.
#[derive(Debug)]
pub(super) struct ByCause<C> {
    interval: Duration,
    last: Option<(C, Instant)>,
}

impl<C: PartialEq> ByCause<C> {
    pub(super) fn new(interval: Duration) -> Self {
        Self {
            interval,
            last: None,
        }
    }

    /// Tells whether `cause` at `now` is let through.
    pub(super) fn ready(&mut self, cause: C, now: Instant) -> bool {
        if let Some((last, at)) = &self.last
            && *last == cause
            && now.saturating_duration_since(*at) < self.interval
        {
            return false;
        }
        self.last = Some((cause, now));
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECOND: Duration = Duration::from_secs(1);

    #[test]
    fn every_lets_one_event_through_per_interval() {
        let start = Instant::now();
        let mut every = Every::new(SECOND);
        assert!(every.ready(start));
        assert!(!every.ready(start));
        assert!(!every.ready(start + Duration::from_millis(999)));
        assert!(every.ready(start + SECOND));
        assert!(!every.ready(start + Duration::from_millis(1500)));
        assert!(every.ready(start + Duration::from_millis(2000)));

        // Ten minutes, as the access error is repeated.
        let ten_minutes = Duration::from_secs(600);
        let mut every = Every::new(ten_minutes);
        assert!(every.ready(start));
        for seconds in (5..600).step_by(5) {
            assert!(
                !every.ready(start + Duration::from_secs(seconds)),
                "{seconds}"
            );
        }
        assert!(every.ready(start + ten_minutes));
    }

    #[test]
    fn counted_reports_how_many_since_the_last_report() {
        let start = Instant::now();
        let minute = Duration::from_secs(60);
        let mut counted = Counted::new(minute);
        assert_eq!(counted.count(start), Some(1));
        assert_eq!(counted.count(start + SECOND), None);
        assert_eq!(counted.count(start + 2 * SECOND), None);
        assert_eq!(counted.count(start + 59 * SECOND), None);
        assert_eq!(counted.count(start + minute), Some(4));
        assert_eq!(counted.count(start + 3 * minute), Some(1));
    }

    #[test]
    fn by_cause_lets_a_changed_cause_through_at_once() {
        let start = Instant::now();
        let ten_minutes = Duration::from_secs(600);
        let mut limit = ByCause::new(ten_minutes);
        assert!(limit.ready("exit 1", start));
        assert!(!limit.ready("exit 1", start + SECOND));
        assert!(limit.ready("spawn", start + 2 * SECOND));
        assert!(limit.ready("exit 1", start + 3 * SECOND));
        assert!(!limit.ready("exit 1", start + 4 * SECOND));
        assert!(!limit.ready("exit 1", start + 2 * SECOND + ten_minutes));
        assert!(limit.ready("exit 1", start + 3 * SECOND + ten_minutes));
    }
}
