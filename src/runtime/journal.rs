//! The journal collector of remote mode, on Linux.
//!
//! The collector reads the host's systemd journal through journalctl, keeps
//! the entries of Clumit Security's own units and containers, and sends each
//! as one Giganto `OpLog` on a stream of its own, at least once, with the
//! journal cursor as its acknowledged position. It follows the log
//! collectors' split: a reader task ([`read`]) runs journalctl and builds
//! the records, and the controller ([`JournalTask`]) alone applies positions,
//! stamps, writes and saves.
//!
//! journalctl runs only while the collector's stream is open: when the
//! stream fails, the controller has the reader stop journalctl before it
//! recovers the stream, and resumes the reader from the acknowledged
//! position once the stream is back. The exceptions are the tail read of a
//! corrupt checkpoint, which runs before the first stream opens, and a host
//! clock step back, after which the controller closes the stream and opens a
//! new one while journalctl waits behind the reader's full channel.

mod entry;
mod gap;
mod limit;
mod lines;
mod read;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::{debug, info, warn};

use self::read::{Event, Initial, Output, ReaderLink, Record, Start};
use super::acks::Acks;
use super::checkpoints::{self, Saves};
use super::{Due, RemoteSender, Stopped, now_nanos, stop_outcome, stopped};
use crate::collector::POLLING_INTERVAL;
use crate::controller::log_reconnect_outcome;
use crate::sender::CloseAck;

/// The position of one journal entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct JournalPosition {
    /// `__CURSOR`.
    pub(super) cursor: String,
    /// `__SEQNUM_ID`, if the entry has one.
    pub(super) seqnum_id: Option<String>,
    /// `__SEQNUM`, if the entry has one that parses.
    pub(super) seqnum: Option<u64>,
    /// `__REALTIME_TIMESTAMP`, in microseconds, if the entry has one that
    /// parses.
    pub(super) realtime_us: Option<u64>,
}

/// What the collector runs and reads; fixed outside tests.
#[derive(Clone, Debug)]
pub(super) struct Paths {
    pub(super) journalctl: PathBuf,
    /// The file holding the machine ID.
    pub(super) machine_id: PathBuf,
    /// The directory holding a journal directory per machine ID.
    pub(super) journal_root: PathBuf,
}

impl Default for Paths {
    fn default() -> Self {
        Self {
            journalctl: PathBuf::from("/usr/bin/journalctl"),
            machine_id: PathBuf::from("/etc/machine-id"),
            journal_root: PathBuf::from("/var/log/journal"),
        }
    }
}

/// What the collector's readers read and how.
#[derive(Clone, Debug)]
pub(super) struct Settings {
    pub(super) paths: Paths,
    /// The state directory, which holds the checkpoint.
    pub(super) state_dir: PathBuf,
    /// How long the reader waits between access checks and between
    /// journalctl runs after a failure.
    pub(super) retry_interval: Duration,
}

/// The task of the journal collector: the controller of its reader.
pub(super) struct JournalTask {
    pub(super) stop: watch::Receiver<bool>,
    pub(super) settings: Settings,
    pub(super) acks: Arc<Acks<JournalPosition>>,
    pub(super) saves: Arc<Saves<JournalPosition>>,
    pub(super) stop_logged: Arc<AtomicBool>,
    /// The task applying the ACKs of the collector's streams.
    pub(super) drain: JoinHandle<()>,
    pub(super) sender: RemoteSender<JournalPosition>,
}

/// What the controller keeps between its steps.
#[derive(Default)]
struct Control {
    /// The reader, while it runs.
    reader: Option<ReaderLink>,
    /// When to start a reader again, while there is none.
    respawn_at: Option<Instant>,
    /// Whether the reader's first result was taken.
    started: bool,
    /// A newly selected starting position whose save has not landed, and
    /// when the save is tried again.
    unsaved: Option<(JournalPosition, Instant)>,
    /// The number of the last resume sent.
    resume: u64,
    due: Option<Due>,
    stamps: Stamps,
}

impl Control {
    /// The next instant the controller acts at without a result; `open`
    /// tells whether the stream is open, so a due resume can be sent.
    fn deadline(&self, open: bool) -> Instant {
        let mut deadline = Instant::now() + POLLING_INTERVAL;
        for at in [
            self.unsaved.as_ref().map(|(_, at)| *at),
            match self.due {
                Some(Due::Current(at)) if open && self.unsaved.is_none() => Some(at),
                _ => None,
            },
            self.respawn_at.filter(|_| self.reader.is_none()),
        ]
        .into_iter()
        .flatten()
        {
            deadline = deadline.min(at);
        }
        deadline
    }
}

/// Stamps the records of one stream with strictly increasing timestamps
/// from their entries' times.
#[derive(Debug, Default)]
struct Stamps {
    /// The previous stamp, `p`.
    previous: Option<i64>,
    /// The time of the previous kept entry with a usable time, `u'`, in
    /// microseconds.
    time: Option<u64>,
}

impl Stamps {
    /// Returns the stamp of an entry of time `u` in microseconds, `p` being
    /// the previous stamp and `u'` the previous entry's time:
    /// `max(u × 1000, p + 1)` if `u > u'` or there is no `u'`, `u × 1000`
    /// for the first entry, and `p + 1` if `u = u'`. Returns `None`, keeping
    /// both, if `u < u'`: the clock stepped back, and the entry belongs on a
    /// new stream.
    ///
    /// An entry without a usable time is stamped `p + 1`, or `now()` as the
    /// first entry, and leaves `u'` as it is.
    fn next(&mut self, realtime_us: Option<u64>, now: impl FnOnce() -> i64) -> Option<i64> {
        let usable =
            realtime_us.and_then(|us| Some((us, i64::try_from(us).ok()?.checked_mul(1000)?)));
        let stamp = match (usable, self.time, self.previous) {
            (Some((us, _)), Some(previous_us), _) if us < previous_us => return None,
            (Some((us, _)), Some(previous_us), Some(previous)) if us == previous_us => {
                previous.saturating_add(1)
            }
            (Some((_, time)), _, Some(previous)) => time.max(previous.saturating_add(1)),
            (Some((_, time)), _, None) => time,
            (None, _, Some(previous)) => previous.saturating_add(1),
            (None, _, None) => now(),
        };
        if let Some((us, _)) = usable {
            self.time = Some(us);
        }
        self.previous = Some(stamp);
        Some(stamp)
    }
}

/// Resolves to the reader's next result, or `None` once it has ended; never
/// resolves while there is no reader.
async fn next_result(reader: &mut Option<ReaderLink>) -> Option<Output> {
    match reader {
        Some(reader) => reader.results.recv().await,
        None => std::future::pending().await,
    }
}

impl JournalTask {
    pub(super) async fn run(mut self) {
        let mut control = Control::default();
        let _ = self.control(&mut control).await;
        // journalctl is stopped before the stream is closed.
        if let Some(reader) = control.reader.take() {
            reader.pause().await;
        }
        drop(control);

        let close = self.sender.close().await;
        if !self.stop_logged.swap(true, Ordering::SeqCst) {
            info!("Stopped the journal collector {}", stop_outcome(&close));
        }
        // Dropping the stream ends its ACK receiver once every ACK it
        // received is applied.
        let Self { sender, drain, .. } = self;
        drop(sender);
        let _ = drain.await;
    }

    /// Runs the collector until it is stopped.
    async fn control(&mut self, control: &mut Control) -> Result<(), Stopped> {
        loop {
            if *self.stop.borrow() {
                return Err(Stopped);
            }
            if control.reader.is_none() && control.respawn_at.is_none_or(|at| Instant::now() >= at)
            {
                self.spawn_reader(control);
            }
            if let Some((position, at)) = &control.unsaved
                && Instant::now() >= *at
            {
                control.unsaved = if self.saves.save(position).await.saved() {
                    None
                } else {
                    Some((position.clone(), Instant::now() + POLLING_INTERVAL))
                };
            }
            if control.started && control.unsaved.is_none() && !self.sender.is_open() {
                self.open_stream(control).await?;
            }
            self.send_resume(control);

            let deadline = control.deadline(self.sender.is_open());
            // journalctl must not run while the stream is down, so a failed
            // stream is replaced at once, whether or not records await their
            // ACK.
            let output = tokio::select! {
                biased;
                () = stopped(&mut self.stop) => return Err(Stopped),
                error = self.sender.failed() => {
                    self.sender.note_failure(&error);
                    self.recover(control).await?;
                    continue;
                }
                output = next_result(&mut control.reader) => output,
                () = tokio::time::sleep_until(deadline) => continue,
            };
            match output {
                Some(output) => self.take(control, output).await?,
                None => self.reader_ended(control),
            }
        }
    }

    /// Starts a reader; until the collector has started, the reader checks
    /// access, loads the checkpoint and chooses where to start.
    fn spawn_reader(&mut self, control: &mut Control) {
        let initial = if control.started {
            Initial::Wait
        } else {
            Initial::Load
        };
        control.reader = Some(read::spawn(self.settings.clone(), initial, control.resume));
        control.respawn_at = None;
    }

    /// The reader ended while the collector runs: a new one is started after
    /// the retry interval and resumed.
    fn reader_ended(&mut self, control: &mut Control) {
        control.reader = None;
        let at = Instant::now() + self.settings.retry_interval;
        control.respawn_at = Some(at);
        if control.started && control.due.is_none() {
            control.due = Some(Due::Current(at));
        }
        warn!(
            "Journal collector: the reader ended; starting it again in {:?}",
            self.settings.retry_interval
        );
    }

    /// Applies a result of the reader.
    async fn take(&mut self, control: &mut Control, output: Output) -> Result<(), Stopped> {
        if output.resume < control.resume {
            debug!("Dropped a late result of the journal reader");
            return Ok(());
        }
        match output.event {
            Event::Ready(start) => {
                control.started = true;
                self.ready(control, start).await;
            }
            Event::Batch { records, after } => self.write(control, records, after).await?,
            Event::Position(position) => self.acks.consumed(position),
        }
        Ok(())
    }

    /// Sets the acknowledged position the reader's first result says to
    /// start from.
    async fn ready(&mut self, control: &mut Control, start: Start) {
        let file = checkpoints::journal_file(&self.settings.state_dir);
        match start {
            Start::Found(position) => self.acks.load(Some(position)),
            Start::Missing => self.acks.load(None),
            Start::Corrupt {
                reason,
                tail: Some(tail),
            } => {
                warn!(
                    "Checkpoint {} is unusable: {reason}; starting after the newest journal \
                     entry instead, so unsent earlier entries may be skipped",
                    file.display()
                );
                self.start_at(control, tail).await;
            }
            Start::Corrupt { reason, tail: None } => {
                warn!(
                    "Checkpoint {} is unusable: {reason}; the journal is empty, so reading \
                     starts at its oldest entry",
                    file.display()
                );
                self.acks.load(None);
            }
        }
    }

    /// Sets a newly selected starting position as the acknowledged position
    /// and saves it; a save that does not land is retried every
    /// [`POLLING_INTERVAL`], and nothing is sent until it lands.
    async fn start_at(&mut self, control: &mut Control, position: JournalPosition) {
        let outcome = checkpoints::start_at(&self.acks, &self.saves, position.clone()).await;
        self.acks.opened(position.clone());
        control.unsaved = (!outcome.saved()).then(|| (position, Instant::now() + POLLING_INTERVAL));
    }

    /// Opens the collector's first stream and sends its record header.
    async fn open_stream(&mut self, control: &mut Control) -> Result<(), Stopped> {
        let outcome = self.sender.open().await.map_err(|_| Stopped)?;
        log_reconnect_outcome(outcome);
        control.stamps = Stamps::default();
        if self.sender.send_header().await.is_err() {
            self.recover(control).await?;
        }
        control.due = Some(Due::Acknowledged);
        Ok(())
    }

    /// Replaces a failed stream: journalctl is stopped first, the records
    /// read and not written are discarded, and the reader resumes from the
    /// acknowledged position on the new stream.
    async fn recover(&mut self, control: &mut Control) -> Result<(), Stopped> {
        if let Some(reader) = &control.reader {
            tokio::select! {
                biased;
                () = stopped(&mut self.stop) => return Err(Stopped),
                () = reader.pause() => {}
            }
        }
        loop {
            let outcome = self.sender.reconnect().await.map_err(|_| Stopped)?;
            log_reconnect_outcome(outcome);
            self.acks.dropped();
            control.stamps = Stamps::default();
            if self.sender.send_header().await.is_ok() {
                break;
            }
        }
        control.due = Some(Due::Acknowledged);
        Ok(())
    }

    /// Sends the resume that is due, once the stream is ready and no
    /// starting position is unsaved. A resume without a position reads from
    /// the oldest entry.
    fn send_resume(&mut self, control: &mut Control) {
        if control.unsaved.is_some() || !self.sender.is_open() {
            return;
        }
        let Some(reader) = &control.reader else {
            return;
        };
        let position = match control.due {
            Some(Due::Acknowledged) => self.acks.acknowledged(),
            Some(Due::Current(at)) if Instant::now() >= at => {
                self.acks.current().or_else(|| self.acks.acknowledged())
            }
            _ => return,
        };
        control.due = None;
        control.resume += 1;
        // The current position is the resume's until it reads an entry.
        if let Some(position) = &position {
            self.acks.opened(position.clone());
        }
        reader.resume(control.resume, position);
    }

    /// Writes a batch of records on the stream, and then applies the
    /// position of the entries dropped after them.
    ///
    /// A record whose time steps back from the previous one's is held with
    /// the rest of the batch: the records before it are written, the stream
    /// is closed and replaced by a new one, and the held records are written
    /// there, the held one first.
    async fn write(
        &mut self,
        control: &mut Control,
        mut records: Vec<Record>,
        after: Option<JournalPosition>,
    ) -> Result<(), Stopped> {
        if *self.stop.borrow() {
            return Err(Stopped);
        }
        // A batch of a resume sent on this stream is never taken before the
        // stream is ready.
        if control.unsaved.is_some() || control.due.is_some() || !self.sender.is_open() {
            return Ok(());
        }
        while !records.is_empty() {
            let mut events = Vec::with_capacity(records.len());
            let mut last = None;
            let mut held = Vec::new();
            let mut rest = records.into_iter();
            while let Some(record) = rest.next() {
                let Some(stamp) = control.stamps.next(record.position.realtime_us, now_nanos)
                else {
                    held.push(record);
                    held.extend(rest);
                    break;
                };
                last = Some(record.position);
                events.push((stamp, record.data));
            }
            if let Some(last) = last {
                self.acks.returned(last);
                if self.sender.write(&events).await.is_err() {
                    self.recover(control).await?;
                    return Ok(());
                }
            }
            if !held.is_empty() && !self.switch(control).await? {
                return Ok(());
            }
            records = held;
        }
        if let Some(after) = after {
            self.acks.consumed(after);
        }
        Ok(())
    }

    /// Replaces the stream after the host clock stepped back: closes it with
    /// its close marker, waits until its close ACK is applied, and opens a
    /// new stream on the same connection, which starts the stamps afresh.
    /// The reader goes on meanwhile, held back by its channel.
    ///
    /// Returns `false` if the stream was recovered as a dropped one instead,
    /// because the close ACK did not arrive or the new stream failed.
    async fn switch(&mut self, control: &mut Control) -> Result<bool, Stopped> {
        info!("Journal collector: the host clock stepped back; continuing on a new stream");
        let close = self.sender.close().await;
        if !matches!(close, Ok(CloseAck::Received)) {
            warn!(
                "Journal collector: closed the stream before a clock step back {}; reading \
                 again from the last acknowledged entry",
                stop_outcome(&close)
            );
            self.recover(control).await?;
            return Ok(false);
        }
        // The close ACK reaches the queue through the ACK task; opening the
        // new stream before it is applied would discard it.
        tokio::select! {
            biased;
            () = stopped(&mut self.stop) => return Err(Stopped),
            () = self.acks.emptied() => {}
        }
        let outcome = self.sender.open().await.map_err(|_| Stopped)?;
        log_reconnect_outcome(outcome);
        control.stamps = Stamps::default();
        if self.sender.send_header().await.is_err() {
            self.recover(control).await?;
            return Ok(false);
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests;
