#[path = "../src/lifecycle.rs"]
mod lifecycle;

use std::time::{Duration, UNIX_EPOCH};

#[test]
fn wall_clock_gaps_and_rollback_trigger_recovery() {
    let start = UNIX_EPOCH + Duration::from_secs(100);
    assert!(!lifecycle::monitor_gap(
        start,
        start + lifecycle::MONITOR_INTERVAL
    ));
    assert!(!lifecycle::monitor_gap(
        start,
        start + Duration::from_secs(13)
    ));
    assert!(lifecycle::monitor_gap(
        start,
        start + Duration::from_secs(14)
    ));
    assert!(lifecycle::monitor_gap(
        start,
        start + Duration::from_secs(3600)
    ));
    assert!(lifecycle::monitor_gap(
        start,
        start - Duration::from_secs(1)
    ));
}
