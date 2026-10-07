//! DNS-through-the-tunnel via systemd-resolved's per-link configuration.
//!
//! The tunnel link gets the profile's resolvers, the routing domain `~.` (every name is
//! routed to it) and `default-route yes`. Removing the link, or `resolvectl revert`,
//! restores resolved's previous behavior: nothing global is rewritten, and
//! `/etc/resolv.conf` is never touched.
//!
//! Limits (see docs/client.md): resolved may still consult other links for names matching
//! *their* routing domains. With the kill switch on, such queries cannot leave the machine
//! (only the tunnel may carry traffic); with it off, DNS protection is partial. Resolvers
//! other than systemd-resolved are not supported; the service refuses to claim DNS
//! protection for them.
use crate::ClientError;
use lovpn_sys::exec::{Cmd, Program, Runner};
use std::{net::IpAddr, path::PathBuf};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    Resolved,
    /// DNS is not managed; status reports DNS as unprotected.
    Unmanaged,
}

#[derive(Clone, Debug)]
pub struct DnsBackend {
    pub kind: Kind,
    pub resolv_conf: PathBuf,
    /// Where resolved keeps the files `/etc/resolv.conf` must point into.
    pub resolved_dir: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DnsObservation {
    Unmanaged,
    Ok,
    Mismatch(&'static str),
    Unknown,
}

impl DnsBackend {
    pub fn new(kind: Kind) -> Self {
        Self {
            kind,
            resolv_conf: PathBuf::from("/etc/resolv.conf"),
            resolved_dir: PathBuf::from("/run/systemd/resolve"),
        }
    }

    /// Whether DNS can be managed here: resolved answers *and* the system actually
    /// resolves through it (`/etc/resolv.conf` is resolved's stub or managed file).
    pub fn available(&self, runner: &dyn Runner) -> bool {
        match self.kind {
            Kind::Unmanaged => true,
            Kind::Resolved => {
                let answers = runner
                    .run(
                        &Cmd::new(Program::Resolvectl, &["status", "--no-pager"]),
                        "inspect-resolver",
                    )
                    .is_ok_and(|out| out.success);
                let uses_resolved = std::fs::canonicalize(&self.resolv_conf)
                    .is_ok_and(|path| path.starts_with(&self.resolved_dir));
                answers && uses_resolved
            }
        }
    }

    pub fn apply(
        &self,
        runner: &dyn Runner,
        interface: &str,
        servers: &[IpAddr],
    ) -> Result<(), ClientError> {
        if self.kind == Kind::Unmanaged {
            return Ok(());
        }
        let mut dns = vec!["dns", interface];
        let rendered: Vec<String> = servers.iter().map(ToString::to_string).collect();
        dns.extend(rendered.iter().map(String::as_str));
        for (args, step) in [
            (dns, "configure-dns"),
            (vec!["domain", interface, "~."], "configure-dns-domain"),
            (
                vec!["default-route", interface, "yes"],
                "configure-dns-route",
            ),
        ] {
            let out = runner.run(&Cmd::new(Program::Resolvectl, &args), step)?;
            if !out.success {
                return Err(ClientError::CommandFailed(step));
            }
        }
        // Best effort: stale answers cached before the tunnel existed.
        let _ = runner.run(
            &Cmd::new(Program::Resolvectl, &["flush-caches"]),
            "flush-dns",
        );
        Ok(())
    }

    /// Best-effort removal of per-link settings (the link usually vanishes anyway).
    pub fn revert(&self, runner: &dyn Runner, interface: &str) {
        if self.kind == Kind::Resolved {
            let _ = runner.run(
                &Cmd::new(Program::Resolvectl, &["revert", interface]),
                "revert-dns",
            );
        }
    }

    pub fn observe(
        &self,
        runner: &dyn Runner,
        interface: &str,
        servers: &[IpAddr],
    ) -> DnsObservation {
        if self.kind == Kind::Unmanaged {
            return DnsObservation::Unmanaged;
        }
        let ask = |verb: &str| {
            runner
                .run(
                    &Cmd::new(Program::Resolvectl, &[verb, interface]),
                    "inspect-dns",
                )
                .ok()
                .filter(|out| out.success)
                .map(|out| out.stdout)
        };
        let (Some(dns), Some(domain), Some(route)) =
            (ask("dns"), ask("domain"), ask("default-route"))
        else {
            return DnsObservation::Unknown;
        };
        let mut configured = parse_link_values(&dns);
        configured.sort();
        let mut wanted: Vec<String> = servers.iter().map(ToString::to_string).collect();
        wanted.sort();
        if configured != wanted {
            return DnsObservation::Mismatch("dns-servers-differ");
        }
        if !parse_link_values(&domain).iter().any(|d| d == "~.") {
            return DnsObservation::Mismatch("dns-not-default-routed");
        }
        if parse_link_values(&route) != ["yes"] {
            return DnsObservation::Mismatch("dns-default-route-off");
        }
        DnsObservation::Ok
    }
}

/// Values after the `Link N (name):` prefix of a `resolvectl <verb> <link>` line.
pub fn parse_link_values(output: &str) -> Vec<String> {
    output
        .lines()
        .filter_map(|line| line.split_once(':'))
        .flat_map(|(_, values)| {
            values
                .split_whitespace()
                .map(String::from)
                .collect::<Vec<_>>()
        })
        .collect()
}
