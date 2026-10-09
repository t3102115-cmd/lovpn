#[path = "../src/lifecycle.rs"]
mod lifecycle;

use std::time::{Duration, Instant, UNIX_EPOCH};

#[test]
fn repair_notifications_back_off_and_keep_periodic_deadline() {
    let start = Instant::now();
    let mut schedule = lifecycle::MonitorSchedule::new(start);
    let mut ticks = Vec::new();
    for millis in (0..=12000).step_by(100) {
        let now = start + Duration::from_millis(millis);
        if schedule.due(now, true, false) {
            ticks.push(millis);
            schedule.completed(now, true);
        }
    }
    assert_eq!(ticks, [0, 500, 1500, 3000, 6000, 9000, 12000]);
}

#[test]
fn real_uplink_notification_during_backoff_is_retained() {
    let start = Instant::now();
    let mut schedule = lifecycle::MonitorSchedule::new(start);
    assert!(schedule.due(start, true, false));
    schedule.completed(start, true);
    assert!(!schedule.due(start + Duration::from_millis(100), true, false));
    assert!(!schedule.due(start + Duration::from_millis(400), false, false));
    assert!(schedule.due(start + Duration::from_millis(500), false, false));
    schedule.completed(start + Duration::from_millis(500), false);
    assert!(schedule.due(start + Duration::from_secs(3), false, false));
}

#[test]
fn resume_bypasses_backoff_and_long_operations_do_not_catch_up() {
    let start = Instant::now();
    let mut schedule = lifecycle::MonitorSchedule::new(start);
    assert!(schedule.due(start, true, false));
    schedule.completed(start, true);
    assert!(schedule.due(start + Duration::from_millis(100), false, true));
    let finished = start + Duration::from_secs(30);
    schedule.completed(finished, true);
    assert!(!schedule.due(finished, false, false));
    assert!(schedule.due(finished + lifecycle::MONITOR_INTERVAL, false, false));
}

#[test]
fn healthy_observation_resets_event_backoff_without_postponing_poll() {
    let start = Instant::now();
    let mut schedule = lifecycle::MonitorSchedule::new(start);
    for millis in [0, 500, 1500] {
        let now = start + Duration::from_millis(millis);
        assert!(schedule.due(now, true, false));
        schedule.completed(now, true);
    }
    let poll = start + lifecycle::MONITOR_INTERVAL;
    assert!(schedule.due(poll, false, false));
    schedule.completed(poll, false);
    assert!(!schedule.due(poll + Duration::from_millis(100), true, false));
    assert!(schedule.due(poll + Duration::from_millis(250), false, false));
    schedule.completed(poll + Duration::from_millis(250), false);
    assert!(schedule.due(start + Duration::from_secs(6), false, false));
}

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

mod properties {
    use super::lifecycle;
    use proptest::prelude::*;
    use std::time::{Duration, Instant};

    proptest! {
        /// Whatever the event pattern, the schedule keeps its periodic deadline and cannot
        /// be driven into a catch-up loop: ticks are bounded by the backoff floor.
        #[test]
        fn event_storms_cannot_starve_or_flood_the_monitor(
            pattern in proptest::collection::vec((0u64..400, any::<bool>(), any::<bool>()), 1..300)
        ) {
            let start = Instant::now();
            let mut schedule = lifecycle::MonitorSchedule::new(start);
            let (mut now_ms, mut ticks) = (0u64, 0u64);
            for (step, changed, mutated) in pattern {
                now_ms += step;
                let now = start + Duration::from_millis(now_ms);
                if schedule.due(now, changed, false) {
                    ticks += 1;
                    schedule.completed(now, mutated);
                }
            }
            // Bounded: event ticks respect the 250 ms floor; periodic ticks come every 3 s.
            prop_assert!(ticks <= now_ms / 250 + now_ms / 3000 + 2);
            // A quiet schedule still fires on its periodic deadline.
            let late = start + Duration::from_millis(now_ms + 3001);
            prop_assert!(schedule.due(late, false, false));
        }
    }
}
