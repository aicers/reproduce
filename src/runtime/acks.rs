//! The acknowledged position of one collector.
//!
//! [`Acks`] keeps one entry per batch written on the collector's current
//! stream: the timestamp of the batch's last event and the position just
//! past it. Giganto's ACKs acknowledge entries in queue order, and the
//! acknowledged position follows them. Positions are opaque: they are kept,
//! compared for equality and handed on, never looked into.
//!
//! The reader's reports go through the same lock, so the acknowledged
//! position is computed from one consistent view of the queue and the
//! reader.

use std::collections::VecDeque;
use std::sync::{Mutex, MutexGuard, PoisonError};

use tokio::sync::Notify;

use crate::sender::CHANNEL_CLOSE_TIMESTAMP;

/// The queue and the acknowledged position of one collector.
pub(super) struct Acks<P> {
    state: Mutex<State<P>>,
    /// Notified whenever the acknowledged position changes.
    changed: Notify,
    /// Notified at every stream replacement.
    replaced: Notify,
    /// Notified when an ACK leaves no entry queued.
    emptied: Notify,
}

struct State<P> {
    /// The batches written on the current stream and not yet acknowledged,
    /// oldest first.
    entries: VecDeque<Entry<P>>,
    next_id: u64,
    /// Incremented at every stream replacement.
    generation: u64,
    /// The generation at which the current ACK receiver was installed.
    receiver: u64,
    acknowledged: Option<P>,
    /// Incremented whenever `acknowledged` changes.
    version: u64,
    /// The reader's current position; `None` after a reader holding a
    /// batch was dropped, until the next reader reports.
    current: Option<P>,
    /// Whether the reader holds a batch it returned and that is not sent
    /// yet. Its position is `current`.
    held: bool,
    /// Whether moving the acknowledged position to the reader's position
    /// while nothing is pending (rule (b)) is suspended, because a stream
    /// replacement dropped unacknowledged entries.
    suspended: bool,
}

struct Entry<P> {
    id: u64,
    timestamp: i64,
    position: P,
}

impl<P: Clone + PartialEq> Acks<P> {
    pub(super) fn new() -> Self {
        Self {
            state: Mutex::new(State {
                entries: VecDeque::new(),
                next_id: 0,
                generation: 0,
                receiver: 0,
                acknowledged: None,
                version: 0,
                current: None,
                held: false,
                suspended: false,
            }),
            changed: Notify::new(),
            replaced: Notify::new(),
            emptied: Notify::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State<P>> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Sets the acknowledged position to the loaded checkpoint, which is
    /// already saved.
    pub(super) fn load(&self, position: Option<P>) {
        self.lock().acknowledged = position;
    }

    /// Returns the acknowledged position.
    pub(super) fn acknowledged(&self) -> Option<P> {
        self.lock().acknowledged.clone()
    }

    /// Returns the acknowledged position and the number of times it has
    /// changed.
    pub(super) fn snapshot(&self) -> (u64, Option<P>) {
        let state = self.lock();
        (state.version, state.acknowledged.clone())
    }

    /// Returns the number of times the acknowledged position has changed.
    pub(super) fn version(&self) -> u64 {
        self.lock().version
    }

    /// Resolves after the acknowledged position changes. A change made
    /// while nobody waits is kept for the next wait.
    pub(super) async fn changed(&self) {
        self.changed.notified().await;
    }

    /// Resolves once no entry is queued: at once if none is, or else when
    /// an ACK acknowledges the last one.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(super) async fn emptied(&self) {
        loop {
            let notified = self.emptied.notified();
            tokio::pin!(notified);
            // Registered before the check, so an ACK applied in between is
            // not missed.
            notified.as_mut().enable();
            if self.lock().entries.is_empty() {
                return;
            }
            notified.await;
        }
    }

    /// Returns the reader's current position.
    pub(super) fn current(&self) -> Option<P> {
        self.lock().current.clone()
    }

    /// A reader opened its file at `position`; its reports replace those of
    /// any reader before it.
    pub(super) fn opened(&self, position: P) {
        let mut state = self.lock();
        state.held = false;
        self.report_current(&mut state, position);
    }

    /// The reader consumed a line it does not return.
    pub(super) fn consumed(&self, position: P) {
        let mut state = self.lock();
        self.report_current(&mut state, position);
    }

    /// The reader returns a batch ending just before `position` and holds
    /// it until it is sent.
    pub(super) fn returned(&self, position: P) {
        let mut state = self.lock();
        state.current = Some(position);
        state.held = true;
    }

    /// The reader was dropped. A batch it held was never written, so its
    /// position is forgotten with the held mark.
    pub(super) fn dropped(&self) {
        let mut state = self.lock();
        if state.held {
            state.held = false;
            state.current = None;
        }
    }

    /// Rule (b): with nothing pending, the acknowledged position follows
    /// the reader.
    fn report_current(&self, state: &mut State<P>, position: P) {
        state.current = Some(position.clone());
        if !state.held && state.entries.is_empty() && !state.suspended {
            self.set_acknowledged(state, position);
        }
    }

    fn set_acknowledged(&self, state: &mut State<P>, position: P) {
        if state.acknowledged.as_ref() != Some(&position) {
            state.acknowledged = Some(position);
            state.version += 1;
            self.changed.notify_one();
        }
    }

    /// Queues the batch the reader holds, whose last event has `timestamp`,
    /// before it is written. Returns the entry's id, or `None` if the reader
    /// has reported no position.
    pub(super) fn queue(&self, timestamp: i64) -> Option<u64> {
        let mut state = self.lock();
        let position = state.current.clone()?;
        let id = state.next_id;
        state.next_id += 1;
        state.entries.push_back(Entry {
            id,
            timestamp,
            position,
        });
        Some(id)
    }

    /// The held batch was written.
    pub(super) fn sent(&self) {
        self.lock().held = false;
    }

    /// Writing the batch of entry `id` failed: the entry is removed, unless
    /// an ACK has already acknowledged it.
    pub(super) fn failed(&self, id: u64) {
        let mut state = self.lock();
        if let Some(index) = state.entries.iter().position(|entry| entry.id == id) {
            state.entries.remove(index);
        }
    }

    /// Resolves after a stream replacement. A replacement made while nobody
    /// waits is kept for the next wait.
    ///
    /// A wait for an ACK that started before a replacement is restarted
    /// then, so the first ACKs of the new stream are not discarded.
    pub(super) async fn replaced(&self) {
        self.replaced.notified().await;
    }

    /// Returns the current stream generation, to be read before waiting
    /// for an ACK and passed to [`apply`](Self::apply) with it.
    pub(super) fn generation(&self) -> u64 {
        self.lock().generation
    }

    /// A new stream replaced the current one; `new_receiver` tells whether
    /// it came with a new ACK receiver. Drops every queued entry, and
    /// suspends rule (b) if there was one. Returns the new generation, which
    /// identifies a new receiver.
    pub(super) fn replace(&self, new_receiver: bool) -> u64 {
        let mut state = self.lock();
        state.generation += 1;
        if new_receiver {
            state.receiver = state.generation;
        }
        if !state.entries.is_empty() {
            state.entries.clear();
            state.suspended = true;
        }
        self.replaced.notify_one();
        state.generation
    }

    /// Applies the ACK `timestamp`, received by the receiver installed at
    /// generation `receiver` from a wait that started at `generation`.
    ///
    /// The ACK is discarded if a replacement happened since, or the
    /// receiver is no longer the current one. A data ACK acknowledges every
    /// entry through the oldest one with an equal timestamp; the close ACK
    /// acknowledges every entry. Returns whether an entry was acknowledged.
    pub(super) fn apply(&self, timestamp: i64, generation: u64, receiver: u64) -> bool {
        let mut state = self.lock();
        if generation != state.generation || receiver != state.receiver {
            return false;
        }
        let count = if timestamp == CHANNEL_CLOSE_TIMESTAMP {
            state.entries.len()
        } else {
            state
                .entries
                .iter()
                .position(|entry| entry.timestamp == timestamp)
                .map_or(0, |index| index + 1)
        };
        let Some(last) = state.entries.drain(..count).last() else {
            return false;
        };
        if state.entries.is_empty() {
            self.emptied.notify_waiters();
        }
        state.suspended = false;
        // Rule (a).
        let position = match &state.current {
            Some(current) if state.entries.is_empty() && !state.held => current.clone(),
            _ => last.position,
        };
        self.set_acknowledged(&mut state, position);
        true
    }

    /// Rule (c): drops every queued entry and sets the acknowledged position
    /// to the starting position `position`, in one step.
    pub(super) fn start(&self, position: P) {
        let mut state = self.lock();
        state.entries.clear();
        state.suspended = false;
        self.set_acknowledged(&mut state, position);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An opaque test position.
    type Pos = &'static str;

    /// A queue whose current stream is the first one with its receiver.
    fn acks() -> (Acks<Pos>, u64) {
        let acks = Acks::new();
        let receiver = acks.replace(true);
        (acks, receiver)
    }

    /// Writes one batch ending at `position` with last timestamp
    /// `timestamp`.
    fn write(acks: &Acks<Pos>, timestamp: i64, position: Pos) {
        acks.returned(position);
        acks.queue(timestamp)
            .expect("the reader reported a position");
        acks.sent();
    }

    fn ack(acks: &Acks<Pos>, receiver: u64, timestamp: i64) -> bool {
        acks.apply(timestamp, acks.generation(), receiver)
    }

    #[test]
    fn data_and_close_acks_acknowledge_entries() {
        let (acks, receiver) = acks();
        acks.opened("0");
        assert_eq!(acks.acknowledged(), Some("0"));
        write(&acks, 10, "a");
        write(&acks, 20, "b");
        write(&acks, 30, "c");

        assert!(ack(&acks, receiver, 20));
        assert_eq!(acks.acknowledged(), Some("b"));
        // An ACK equal to no queued entry changes nothing.
        assert!(!ack(&acks, receiver, 20));
        assert!(!ack(&acks, receiver, 99));
        assert_eq!(acks.acknowledged(), Some("b"));

        write(&acks, 40, "d");
        assert!(ack(&acks, receiver, CHANNEL_CLOSE_TIMESTAMP));
        assert_eq!(acks.acknowledged(), Some("d"));
    }

    #[tokio::test]
    async fn emptied_waits_until_an_ack_leaves_nothing_queued() {
        let (acks, receiver) = acks();
        acks.opened("0");
        // Nothing queued: it resolves at once.
        acks.emptied().await;

        write(&acks, 10, "a");
        write(&acks, 20, "b");
        let acks = std::sync::Arc::new(acks);
        let waiter = tokio::spawn({
            let acks = acks.clone();
            async move { acks.emptied().await }
        });
        tokio::task::yield_now().await;
        assert!(ack(&acks, receiver, 10));
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished(), "an entry is still queued");
        assert!(ack(&acks, receiver, CHANNEL_CLOSE_TIMESTAMP));
        tokio::time::timeout(std::time::Duration::from_secs(5), waiter)
            .await
            .expect("resolved")
            .expect("the waiter ran");
        assert_eq!(acks.acknowledged(), Some("b"));
    }

    #[test]
    fn a_missing_close_ack_leaves_the_last_data_acknowledgement() {
        let (acks, receiver) = acks();
        acks.opened("0");
        write(&acks, 10, "a");
        write(&acks, 20, "b");
        assert!(ack(&acks, receiver, 10));
        // The close ACK never arrives.
        assert_eq!(acks.acknowledged(), Some("a"));
    }

    #[test]
    fn equal_timestamps_are_consumed_one_ack_at_a_time() {
        let (acks, receiver) = acks();
        acks.opened("0");
        write(&acks, 7, "a");
        write(&acks, 7, "b");
        assert!(ack(&acks, receiver, 7));
        assert_eq!(acks.acknowledged(), Some("a"));
        assert!(ack(&acks, receiver, 7));
        assert_eq!(acks.acknowledged(), Some("b"));
        assert!(!ack(&acks, receiver, 7));
        assert_eq!(acks.acknowledged(), Some("b"));
    }

    #[test]
    fn non_monotonic_timestamps_are_acknowledged_in_queue_order() {
        let (acks, receiver) = acks();
        acks.opened("0");
        write(&acks, 50, "a");
        write(&acks, 30, "b");
        write(&acks, 40, "c");
        // 30 is lower than the first entry's 50, yet acknowledges through b.
        assert!(ack(&acks, receiver, 30));
        assert_eq!(acks.acknowledged(), Some("b"));
        assert!(ack(&acks, receiver, 40));
        assert_eq!(acks.acknowledged(), Some("c"));
    }

    #[test]
    fn rule_a_uses_the_reader_position_only_when_nothing_is_pending() {
        let (acks, receiver) = acks();
        acks.opened("0");
        write(&acks, 1, "a");
        write(&acks, 2, "b");
        // Entries still queued: the last entry acknowledged.
        assert!(ack(&acks, receiver, 1));
        assert_eq!(acks.acknowledged(), Some("a"));

        // A held batch: the last entry acknowledged, not the held position.
        acks.returned("c");
        assert!(ack(&acks, receiver, 2));
        assert_eq!(acks.acknowledged(), Some("b"));

        // Queue empty and nothing held: the reader's position, past the
        // empty lines it consumed since.
        acks.queue(3).expect("queued");
        acks.sent();
        acks.consumed("c+empty");
        assert_eq!(acks.acknowledged(), Some("b"));
        assert!(ack(&acks, receiver, 3));
        assert_eq!(acks.acknowledged(), Some("c+empty"));
    }

    #[test]
    fn rule_b_follows_the_reader_while_idle() {
        let (acks, receiver) = acks();
        acks.opened("0");
        write(&acks, 1, "a");
        // Pending: the reader's reports do not move it.
        acks.consumed("a+1");
        assert_eq!(acks.acknowledged(), Some("0"));
        assert!(ack(&acks, receiver, 1));
        assert_eq!(acks.acknowledged(), Some("a+1"));
        acks.consumed("a+2");
        assert_eq!(acks.acknowledged(), Some("a+2"));
        // A held batch stops it.
        acks.returned("b");
        acks.consumed("b+1");
        assert_eq!(acks.acknowledged(), Some("a+2"));
    }

    #[test]
    fn a_replacement_that_drops_entries_suspends_rule_b() {
        let (acks, receiver) = acks();
        acks.opened("0");
        write(&acks, 1, "a");
        write(&acks, 2, "b");
        assert!(ack(&acks, receiver, 1));
        assert_eq!(acks.acknowledged(), Some("a"));

        // The stream is reopened with b unacknowledged.
        acks.replace(false);
        assert_eq!(acks.acknowledged(), Some("a"));
        // A late ACK of the dropped entry acknowledges nothing.
        assert!(!ack(&acks, receiver, 2));
        assert_eq!(acks.acknowledged(), Some("a"));
        // The idle reader does not move it either.
        acks.consumed("b+1");
        assert_eq!(acks.acknowledged(), Some("a"));

        // An entry acknowledged on the new stream lifts the suspension.
        write(&acks, 3, "c");
        assert!(ack(&acks, receiver, 3));
        assert_eq!(acks.acknowledged(), Some("c"));
        acks.consumed("c+1");
        assert_eq!(acks.acknowledged(), Some("c+1"));
    }

    #[test]
    fn a_replacement_without_entries_keeps_rule_b() {
        let (acks, receiver) = acks();
        acks.opened("0");
        write(&acks, 1, "a");
        assert!(ack(&acks, receiver, 1));
        acks.replace(false);
        acks.consumed("a+1");
        assert_eq!(acks.acknowledged(), Some("a+1"));
    }

    #[test]
    fn an_ack_received_before_a_replacement_is_discarded() {
        let (acks, receiver) = acks();
        acks.opened("0");
        write(&acks, 1, "a");
        // The wait for the ACK starts before the replacement.
        let generation = acks.generation();
        acks.replace(false);
        write(&acks, 1, "b");
        assert!(!acks.apply(1, generation, receiver));
        assert_eq!(acks.acknowledged(), Some("0"));
        assert!(ack(&acks, receiver, 1));
        assert_eq!(acks.acknowledged(), Some("b"));
    }

    #[tokio::test]
    async fn a_replacement_wakes_the_wait_for_acks() {
        let (acks, _) = acks();
        // The replacement that installed the receiver is kept for the next
        // wait.
        tokio::time::timeout(std::time::Duration::from_secs(1), acks.replaced())
            .await
            .expect("the replacement is notified");
        acks.replace(false);
        tokio::time::timeout(std::time::Duration::from_secs(1), acks.replaced())
            .await
            .expect("the replacement is notified");
    }

    #[test]
    fn a_replaced_receiver_is_ignored() {
        let (acks, old) = acks();
        acks.opened("0");
        let new = acks.replace(true);
        write(&acks, 1, "a");
        // The generation is current, but the receiver is not.
        assert!(!ack(&acks, old, 1));
        assert!(ack(&acks, new, 1));
        assert_eq!(acks.acknowledged(), Some("a"));
    }

    #[test]
    fn an_ack_during_the_write_acknowledges_the_entry() {
        let (acks, receiver) = acks();
        acks.opened("0");
        acks.returned("a");
        let id = acks.queue(1).expect("queued");
        // The ACK arrives before the write returns.
        assert!(ack(&acks, receiver, 1));
        assert_eq!(acks.acknowledged(), Some("a"));
        // A failure reported afterwards removes nothing more.
        acks.failed(id);
        assert_eq!(acks.acknowledged(), Some("a"));
    }

    #[test]
    fn a_failed_write_removes_its_unacknowledged_entry() {
        let (acks, receiver) = acks();
        acks.opened("0");
        acks.returned("a");
        let id = acks.queue(1).expect("queued");
        acks.failed(id);
        assert!(!ack(&acks, receiver, 1));
        assert_eq!(acks.acknowledged(), Some("0"));
        // The batch is re-sent and queued once.
        let _ = acks.queue(2).expect("queued");
        acks.sent();
        assert!(ack(&acks, receiver, 2));
        assert_eq!(acks.acknowledged(), Some("a"));
    }

    #[test]
    fn a_dropped_reader_that_held_a_batch_is_not_passed() {
        let (acks, receiver) = acks();
        acks.opened("0");
        write(&acks, 1, "a");
        acks.returned("b");
        acks.dropped();
        assert_eq!(acks.current(), None);
        // Rule (a) uses the last entry acknowledged, not b.
        assert!(ack(&acks, receiver, 1));
        assert_eq!(acks.acknowledged(), Some("a"));
        // The next reader's reports apply again.
        acks.opened("0'");
        assert_eq!(acks.acknowledged(), Some("0'"));
    }

    #[test]
    fn a_dropped_reader_without_a_batch_keeps_its_position() {
        let (acks, _) = acks();
        acks.opened("0");
        acks.consumed("1");
        acks.dropped();
        assert_eq!(acks.current(), Some("1"));
        assert_eq!(acks.acknowledged(), Some("1"));
    }

    #[test]
    fn the_starting_position_drops_entries() {
        let (acks, receiver) = acks();
        acks.load(Some("saved"));
        acks.opened("0");
        write(&acks, 1, "a");
        write(&acks, 2, "b");
        acks.replace(false);
        write(&acks, 3, "c");

        acks.start("start");
        assert_eq!(acks.acknowledged(), Some("start"));
        // A late ACK of a dropped entry is ignored.
        assert!(!ack(&acks, receiver, 3));
        // While later entries are pending, the acknowledged position, which
        // every save carries, stays at the starting position.
        write(&acks, 4, "d");
        write(&acks, 5, "e");
        acks.consumed("e+1");
        assert_eq!(acks.snapshot().1, Some("start"));
        assert!(ack(&acks, receiver, 4));
        assert_eq!(acks.acknowledged(), Some("d"));
    }

    #[test]
    fn the_starting_position_lifts_a_suspension() {
        let (acks, _) = acks();
        acks.opened("0");
        write(&acks, 1, "a");
        acks.replace(false);
        acks.start("start");
        acks.consumed("start+1");
        assert_eq!(acks.acknowledged(), Some("start+1"));
    }

    #[test]
    fn the_version_counts_changes_only() {
        let (acks, _) = acks();
        assert_eq!(acks.version(), 0);
        acks.load(Some("0"));
        assert_eq!(acks.version(), 0);
        acks.opened("0");
        assert_eq!(acks.version(), 0);
        acks.consumed("1");
        assert_eq!(acks.version(), 1);
        acks.consumed("1");
        assert_eq!(acks.version(), 1);
    }
}
