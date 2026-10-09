//! What the tray shows and when it speaks. Pure, so it is tested without a desktop.
//!
//! The rules match the window's (`ui/app.js`): the same state words, and a message only after
//! the same state was seen on two polls in a row, only for the states that need attention,
//! and never with a server name, address or key in it.
use serde_json::Value;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key {
    /// The LoVPN service is not running (or cannot be reached).
    Service,
    Protected,
    Connecting,
    Disconnected,
    Degraded,
    Blocked,
    Unknown,
}

impl Key {
    pub fn from_status(status: Option<&Value>) -> Self {
        let Some(status) = status else {
            return Self::Service;
        };
        if status.get("service").and_then(Value::as_str) != Some("running") {
            return Self::Service;
        }
        match status.get("state").and_then(Value::as_str) {
            Some("protected") => Self::Protected,
            Some("connecting") => Self::Connecting,
            Some("disconnected") => Self::Disconnected,
            Some("degraded") => Self::Degraded,
            Some("blocked") => Self::Blocked,
            _ => Self::Unknown,
        }
    }

    #[cfg(target_os = "linux")]
    /// A standard icon-theme name: no icon file is shipped, and every theme maps these.
    pub fn icon(self) -> &'static str {
        match self {
            Self::Protected => "network-vpn",
            Self::Connecting => "network-vpn-acquiring",
            Self::Disconnected => "network-vpn-disconnected",
            Self::Degraded | Self::Unknown => "dialog-warning",
            Self::Blocked => "network-offline",
            Self::Service => "dialog-error",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Self::Protected => "Protected",
            Self::Connecting => "Connecting",
            Self::Disconnected => "Not connected",
            Self::Degraded => "Protection incomplete",
            Self::Blocked => "Internet blocked by the kill switch",
            Self::Unknown => "Protection cannot be verified",
            Self::Service => "LoVPN service not running",
        }
    }

    pub fn can_connect(self) -> bool {
        matches!(self, Self::Disconnected | Self::Blocked)
    }

    pub fn can_disconnect(self) -> bool {
        matches!(self, Self::Protected | Self::Degraded | Self::Connecting)
    }

    /// The message for arriving at `self` from `prev`, if it deserves one.
    fn notice_from(self, prev: Self) -> Option<&'static str> {
        if prev == self {
            return None;
        }
        match self {
            Self::Degraded => Some("Protection is incomplete. Open LoVPN for details."),
            Self::Blocked => Some("Internet is blocked on purpose by the kill switch."),
            Self::Unknown => Some("LoVPN can't verify your protection right now."),
            Self::Service => Some("The LoVPN service isn't running."),
            Self::Protected
                if matches!(
                    prev,
                    Self::Degraded | Self::Blocked | Self::Unknown | Self::Service
                ) =>
            {
                Some("You're protected again.")
            }
            _ => None,
        }
    }
}

/// Debounces the polls: a state counts only once it was seen twice in a row, and the very
/// first state is never announced (nothing changed yet).
#[derive(Default)]
pub struct Tracker {
    settled: Option<Key>,
    pending: Option<Key>,
}

impl Tracker {
    /// Feed one poll. Returns the message to show, if any.
    pub fn observe(&mut self, now: Key) -> Option<&'static str> {
        if self.settled == Some(now) {
            self.pending = None;
            return None;
        }
        if self.pending != Some(now) {
            self.pending = Some(now);
            return None;
        }
        let prev = self.settled.replace(now);
        self.pending = None;
        prev.and_then(|p| now.notice_from(p))
    }

    pub fn settled(&self) -> Option<Key> {
        self.settled
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    fn run(seq: &[Key]) -> Vec<Option<&'static str>> {
        let mut t = Tracker::default();
        seq.iter().map(|k| t.observe(*k)).collect()
    }

    #[test]
    fn states_come_from_the_service_report_and_default_to_unknown() {
        assert_eq!(Key::from_status(None), Key::Service);
        let up = |s: &str| json!({"service": "running", "state": s});
        assert_eq!(Key::from_status(Some(&up("protected"))), Key::Protected);
        assert_eq!(Key::from_status(Some(&up("blocked"))), Key::Blocked);
        assert_eq!(Key::from_status(Some(&up("who-knows"))), Key::Unknown);
        assert_eq!(
            Key::from_status(Some(&json!({"service": "stopped", "state": "protected"}))),
            Key::Service,
            "a stopped service is never shown as protected"
        );
        assert_eq!(
            Key::from_status(Some(&json!({"state": "protected"}))),
            Key::Service
        );
    }

    #[test]
    fn the_first_state_and_single_sightings_are_silent() {
        use Key::*;
        let out = run(&[Protected, Protected, Degraded, Protected, Protected]);
        assert!(
            out.iter().all(Option::is_none),
            "a one-poll blip must not notify: {out:?}"
        );
    }

    #[test]
    fn a_lasting_change_notifies_once() {
        use Key::*;
        let out = run(&[Protected, Protected, Degraded, Degraded, Degraded, Degraded]);
        assert_eq!(out.iter().flatten().count(), 1);
        assert!(out[3].unwrap().contains("incomplete"));
    }

    #[test]
    fn recovery_is_announced_but_routine_changes_are_not() {
        use Key::*;
        let out = run(&[Blocked, Blocked, Protected, Protected]);
        assert_eq!(out[3], Some("You're protected again."));
        let routine = run(&[
            Disconnected,
            Disconnected,
            Connecting,
            Connecting,
            Protected,
            Protected,
        ]);
        assert!(routine.iter().all(Option::is_none), "{routine:?}");
        let off = run(&[Protected, Protected, Disconnected, Disconnected]);
        assert!(
            off.iter().all(Option::is_none),
            "disconnecting on purpose is silent"
        );
    }

    #[test]
    fn no_message_or_title_can_carry_a_name_address_or_key() {
        for key in [
            Key::Service,
            Key::Protected,
            Key::Connecting,
            Key::Disconnected,
            Key::Degraded,
            Key::Blocked,
            Key::Unknown,
        ] {
            for text in [key.title()]
                .into_iter()
                .chain(Tracker::default().observe(key))
            {
                assert!(!text.contains('=') && !text.contains(':') && !text.contains('/'));
            }
        }
    }

    #[test]
    fn menu_actions_match_the_state() {
        assert!(Key::Disconnected.can_connect() && !Key::Disconnected.can_disconnect());
        assert!(Key::Protected.can_disconnect() && !Key::Protected.can_connect());
        assert!(!Key::Service.can_connect() && !Key::Service.can_disconnect());
        assert!(Key::Blocked.can_connect());
    }
}
