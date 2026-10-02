//! Clipboard auto-clear scheduling, independent of any clipboard backend.
//!
//! Frontends call [`AutoClear::copied`] after placing a value on the clipboard
//! and poll [`AutoClear::due`] (or sleep until [`AutoClear::deadline`]). When a
//! token is due, the frontend asks its `Clipboard` implementation to clear
//! *only if it still holds our value*.

use std::time::{Duration, Instant};

pub const DEFAULT_CLEAR_SECS: u64 = 30;

#[derive(Debug, Clone)]
pub struct AutoClear<T: Copy + Eq> {
    after: Duration,
    pending: Option<(T, Instant)>,
}

impl<T: Copy + Eq> AutoClear<T> {
    pub fn new(after: Duration) -> Self {
        Self {
            after,
            pending: None,
        }
    }

    pub fn after(&self) -> Duration {
        self.after
    }

    /// Change the delay used for future copies. A pending clear is rescheduled
    /// to the new delay so a shorter timeout takes effect immediately.
    pub fn set_after(&mut self, after: Duration) {
        self.after = after;
        if let Some((_, at)) = &mut self.pending {
            *at = Instant::now() + after;
        }
    }

    /// Register a fresh copy. A newer copy supersedes the previous pending clear:
    /// the clipboard no longer holds the older value anyway.
    pub fn copied(&mut self, token: T, now: Instant) -> Instant {
        let at = now + self.after;
        self.pending = Some((token, at));
        at
    }

    pub fn deadline(&self) -> Option<Instant> {
        self.pending.map(|(_, at)| at)
    }

    /// Take the token if its deadline has passed.
    pub fn due(&mut self, now: Instant) -> Option<T> {
        match self.pending {
            Some((t, at)) if now >= at => {
                self.pending = None;
                Some(t)
            }
            _ => None,
        }
    }

    /// Take the pending token immediately (e.g. on lock or quit).
    pub fn flush(&mut self) -> Option<T> {
        self.pending.take().map(|(t, _)| t)
    }

    /// Seconds left, rounded up, for "clears in Ns" labels.
    pub fn remaining_secs(&self, now: Instant) -> Option<u64> {
        self.pending.map(|(_, at)| {
            let d = at.saturating_duration_since(now);
            d.as_secs() + u64::from(d.subsec_nanos() > 0)
        })
    }
}

/// User-facing toast text.
pub fn copied_message(what: &str, after: Duration) -> String {
    format!("{what} copied, clears in {}s", after.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schedules_and_fires_once() {
        let t0 = Instant::now();
        let mut ac = AutoClear::new(Duration::from_secs(30));
        ac.copied(1u64, t0);
        assert_eq!(ac.due(t0 + Duration::from_secs(29)), None);
        assert_eq!(
            ac.remaining_secs(t0 + Duration::from_millis(29_500)),
            Some(1)
        );
        assert_eq!(ac.due(t0 + Duration::from_secs(30)), Some(1));
        assert_eq!(ac.due(t0 + Duration::from_secs(31)), None);
    }

    #[test]
    fn set_after_reschedules_a_pending_clear() {
        let t0 = Instant::now();
        let mut ac = AutoClear::new(Duration::from_secs(30));
        ac.copied(1u64, t0);
        ac.set_after(Duration::from_secs(5));
        assert_eq!(ac.after(), Duration::from_secs(5));
        // The pending copy now clears on the shorter schedule.
        assert_eq!(ac.remaining_secs(Instant::now()), Some(5));
        assert_eq!(ac.due(Instant::now() + Duration::from_secs(6)), Some(1));
    }

    #[test]
    fn newer_copy_supersedes() {
        let t0 = Instant::now();
        let mut ac = AutoClear::new(Duration::from_secs(30));
        ac.copied(1u64, t0);
        ac.copied(2u64, t0 + Duration::from_secs(20));
        assert_eq!(ac.due(t0 + Duration::from_secs(31)), None);
        assert_eq!(ac.due(t0 + Duration::from_secs(50)), Some(2));
    }

    #[test]
    fn flush_and_message() {
        let mut ac = AutoClear::new(Duration::from_secs(30));
        ac.copied(7u64, Instant::now());
        assert_eq!(ac.flush(), Some(7));
        assert_eq!(ac.flush(), None);
        assert_eq!(
            copied_message("Password", ac.after()),
            "Password copied, clears in 30s"
        );
    }
}
