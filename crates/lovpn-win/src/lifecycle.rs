//! Pure monitor timing shared with cross-platform lifecycle tests.
use std::time::{Duration, Instant, SystemTime};

pub(crate) const MONITOR_INTERVAL: Duration = Duration::from_secs(3);
const RESUME_SLACK: Duration = Duration::from_secs(10);

/// Retain notifications during a cooldown; never extend the periodic observation
/// deadline in response to events. Even a continuous self-notification storm is bounded.
pub(crate) struct MonitorSchedule {
    next_poll: Instant,
    next_event: Instant,
    pending: bool,
    backoff: Duration,
}

impl MonitorSchedule {
    pub(crate) fn new(now: Instant) -> Self {
        Self {
            next_poll: now + MONITOR_INTERVAL,
            next_event: now,
            pending: false,
            backoff: Duration::from_millis(250),
        }
    }

    pub(crate) fn due(&mut self, now: Instant, changed: bool, resumed: bool) -> bool {
        self.pending |= changed;
        if resumed || now >= self.next_poll || (self.pending && now >= self.next_event) {
            self.pending = false;
            if now >= self.next_poll || resumed {
                self.next_poll = now + MONITOR_INTERVAL;
            }
            true
        } else {
            false
        }
    }

    pub(crate) fn completed(&mut self, now: Instant, mutated: bool) {
        if mutated {
            self.backoff = (self.backoff * 2).min(MONITOR_INTERVAL);
        } else {
            self.backoff = Duration::from_millis(250);
        }
        self.next_event = now + self.backoff;
        // A long engine operation must not cause a catch-up loop.
        if self.next_poll <= now {
            self.next_poll = now + MONITOR_INTERVAL;
        }
    }
}

pub(crate) fn monitor_gap(previous: SystemTime, current: SystemTime) -> bool {
    current
        .duration_since(previous)
        .map_or(true, |gap| gap > MONITOR_INTERVAL + RESUME_SLACK)
}
