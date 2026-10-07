use crate::Report;
use lovpn_firewall::FirewallPlan;
use serde_json::json;

pub fn privacy() -> Report {
    Report {
        data: json!({
            "schema_version": 1,
            "telemetry": false,
            "crash_reporting": false,
            "third_party_analytics": false,
            "account_required": false,
            "network_connections": [],
            "user_initiated_connections": [
                {"command": "lovpn enroll", "destination": "the server address you give it", "protocol": "TLS 1.3 to a pinned certificate", "sends": "one-time token and your PUBLIC key"},
                {"command": "lovpn connect", "destination": "the server in your profile, through lovpn-clientd", "protocol": "WireGuard", "sends": "tunnel traffic"}
            ],
            "scope": "This offline CLI only; not other applications or build tools",
            "vpn_protection": "not-verified"
        }),
        text: "LoVPN Privacy\n\nAccount required: No\nTelemetry: None\nCrash reporting: None\nThird-party analytics: None\nAutomatic or background connections: None (this CLI)\nConnections only when you ask for them:\n  lovpn enroll  -> the server address you give it (TLS 1.3, pinned certificate; sends a one-time token and your PUBLIC key)\n  lovpn connect -> the server in your profile, through the LoVPN service (WireGuard)\nOther commands only talk to the local LoVPN service. No LoVPN-operated server is ever contacted.\n\nProtection is only reported by `lovpn status` from what the service observes.\nBuild tools and other applications are outside this report's scope.".into(),
    }
}

pub fn status() -> Report {
    Report {
        data: json!({
            "schema_version": 1,
            "version": env!("CARGO_PKG_VERSION"),
            "implementation": "offline-foundation",
            "vpn": "unavailable",
            "ipv4": "not-verified",
            "ipv6": "not-verified",
            "dns": "not-verified",
            "kill_switch": "not-verified",
            "host_state_inspected": false,
            "system_changed": false,
            "reason": "This build has no privileged service, live firewall adapter or VPN backend",
            "next_step": "Validate a public profile with lovpn config validate; follow docs/roadmap.md for live integration"
        }),
        text: "LoVPN — offline foundation\n\nVPN: Unavailable in this build\nIPv4: Not verified\nIPv6: Not verified\nDNS: Not verified\nKill switch: Not verified\n\nThis is a sanitized capability report, not a host network diagnosis.\nNo privileged service or VPN backend is implemented. No system changes were made.\nNext: lovpn config validate <profile.toml>; see docs/roadmap.md for live integration.".into(),
    }
}

pub fn firewall(plan: &FirewallPlan, preview: Option<bool>) -> Report {
    let mut data = json!({
        "schema_version": 1,
        "ok": true,
        "compiler_valid": true,
        "target": "linux-nftables-laboratory",
        "kernel_validated": false,
        "installed": false,
        "protection": "not-verified",
        "system_changed": false,
        "warning": "Allows IPv4 DHCP client traffic (UDP source port 68 to destination port 67) for uplink lease renewal. No NDP/LAN exceptions or lifecycle management. Do not apply this lab policy on your host or a remote machine."
    });
    let text = match preview {
        Some(reset) => {
            let rules = if reset { plan.reset_ruleset() } else { plan.ruleset() };
            data["reset_preview"] = json!(reset);
            data["ruleset"] = json!(rules);
            rules.to_owned()
        }
        None => "Firewall policy compiled successfully (static validation only).\nKernel validation: Not performed\nRules installed: No\nProtection: Not verified\nDo not apply this laboratory policy to your host or a remote machine.".into(),
    };
    Report { data, text }
}
