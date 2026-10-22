//! TLS reload requests shared by every connection of the process.
//!
//! `SIGHUP` asks every connection to reload its TLS material on its next
//! reconnect. Each connection subscribes to one [`ReloadSignal`] and gets its
//! own [`ReloadFlag`], so one connection applying a reload never clears the
//! request for another, and a request that arrives after a reconnect has read
//! its TLS files stays pending for the next reconnect.

use std::sync::Arc;

use tokio::sync::watch;

/// Broadcasts reload requests to every subscribed connection.
///
/// The signal counts requests; a subscriber's flag is pending while the count
/// is ahead of the last request that subscriber applied.
#[derive(Clone, Debug)]
pub struct ReloadSignal {
    requests: Arc<watch::Sender<u64>>,
}

impl Default for ReloadSignal {
    fn default() -> Self {
        Self::new()
    }
}

impl ReloadSignal {
    #[must_use]
    pub fn new() -> Self {
        let (requests, _) = watch::channel(0);
        Self {
            requests: Arc::new(requests),
        }
    }

    /// Sets the reload flag of every connection subscribed so far.
    pub fn request(&self) {
        self.requests.send_modify(|count| *count += 1);
    }

    /// Returns a reload flag for one connection.
    ///
    /// The flag starts cleared: a connection subscribes before it first reads
    /// its TLS files, so the material it reads already reflects every earlier
    /// request, and a request from then on stays pending for its next
    /// reconnect.
    #[must_use]
    pub fn subscribe(&self) -> ReloadFlag {
        let requests = self.requests.subscribe();
        let applied = *requests.borrow();
        ReloadFlag { requests, applied }
    }
}

/// The reload flag of one connection.
#[derive(Debug)]
pub struct ReloadFlag {
    requests: watch::Receiver<u64>,
    applied: u64,
}

/// Records which requests a reconnect's TLS material reflects.
///
/// Taken before the reconnect reads its TLS files and handed back to
/// [`ReloadFlag::commit`] once the connection built from them succeeds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct ReloadTicket(u64);

impl ReloadFlag {
    /// Returns whether a reload was requested after this connection last read
    /// its TLS material.
    #[must_use]
    pub fn is_pending(&self) -> bool {
        *self.requests.borrow() > self.applied
    }

    /// Takes a ticket for the requests made so far, before reading the TLS
    /// files.
    pub fn ticket(&self) -> ReloadTicket {
        ReloadTicket(*self.requests.borrow())
    }

    /// Clears the requests the ticket covers after a successful reconnect
    /// with the material read under it. A request made after the ticket was
    /// taken stays pending.
    pub fn commit(&mut self, ticket: ReloadTicket) {
        self.applied = self.applied.max(ticket.0);
    }

    /// Waits until a reload is pending.
    ///
    /// Returns at once when one already is; never returns if the signal is
    /// dropped without a further request.
    pub async fn requested(&mut self) {
        let applied = self.applied;
        if self
            .requests
            .wait_for(|count| *count > applied)
            .await
            .is_err()
        {
            std::future::pending::<()>().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::time::timeout;

    use super::*;

    #[test]
    fn subscriber_starts_without_a_pending_reload() {
        let signal = ReloadSignal::new();
        signal.request();
        let flag = signal.subscribe();
        assert!(
            !flag.is_pending(),
            "a request made before subscribing is reflected by the first TLS read",
        );
    }

    #[test]
    fn request_sets_every_subscribers_flag() {
        let signal = ReloadSignal::new();
        let first = signal.subscribe();
        let second = signal.subscribe();
        signal.request();
        assert!(first.is_pending());
        assert!(second.is_pending());
    }

    #[test]
    fn commit_clears_only_its_own_flag() {
        let signal = ReloadSignal::new();
        let mut first = signal.subscribe();
        let second = signal.subscribe();
        signal.request();

        let ticket = first.ticket();
        first.commit(ticket);
        assert!(!first.is_pending());
        assert!(
            second.is_pending(),
            "one connection's reload must not clear another's flag",
        );
    }

    #[test]
    fn request_after_ticket_stays_pending_past_commit() {
        let signal = ReloadSignal::new();
        let mut flag = signal.subscribe();
        signal.request();

        let ticket = flag.ticket();
        // A `SIGHUP` after the reconnect has read its TLS files.
        signal.request();
        flag.commit(ticket);
        assert!(
            flag.is_pending(),
            "a request after the TLS read must stay pending for the next reconnect",
        );

        let ticket = flag.ticket();
        flag.commit(ticket);
        assert!(!flag.is_pending());
    }

    #[test]
    fn stale_ticket_does_not_reopen_a_cleared_flag() {
        let signal = ReloadSignal::new();
        let mut flag = signal.subscribe();
        signal.request();
        let stale = flag.ticket();
        signal.request();
        let fresh = flag.ticket();
        flag.commit(fresh);
        flag.commit(stale);
        assert!(!flag.is_pending());
    }

    #[tokio::test]
    async fn requested_waits_for_a_request() {
        let signal = ReloadSignal::new();
        let mut flag = signal.subscribe();
        assert!(
            timeout(Duration::from_millis(50), flag.requested())
                .await
                .is_err(),
            "no request has been made yet",
        );
        signal.request();
        timeout(Duration::from_secs(1), flag.requested())
            .await
            .expect("a request must wake the waiter");
    }
}
