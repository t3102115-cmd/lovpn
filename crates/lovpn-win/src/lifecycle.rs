//! Pure monitor timing shared with cross-platform lifecycle tests.
use std::time::{Duration, SystemTime};

pub(crate) const MONITOR_INTERVAL: Duration = Duration::from_secs(3);
const RESUME_SLACK: Duration = Duration::from_secs(10);

pub(crate) fn monitor_gap(previous: SystemTime, current: SystemTime) -> bool {
    current
        .duration_since(previous)
        .map_or(true, |gap| gap > MONITOR_INTERVAL + RESUME_SLACK)
}
