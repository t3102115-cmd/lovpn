//! Scoped Windows NRPT DNS. A journal must be durably stored before `apply`.
//! No existing policy is replaced: restoration removes only exact owned rules.
//! NRPT governs the Windows resolver, not applications using DoH or private DNS.
pub use lovpn_config::DnsScope as Scope;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Journal {
    /// Random per-session 128-bit token, lowercase hexadecimal; never reuse it.
    pub owner: String,
    pub scopes: Vec<Scope>,
}

impl Journal {
    /// Validation is repeated on restoration because journals are untrusted input.
    pub fn validate(&self) -> Result<(), String> {
        if self.owner.len() != 32
            || !self
                .owner
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("invalid NRPT ownership token".into());
        }
        if self.scopes.is_empty() || self.scopes.len() > 32 {
            return Err("NRPT requires 1..32 scopes".into());
        }
        lovpn_config::validate_dns_scopes(&self.scopes).map_err(|_| "invalid NRPT scopes".into())
    }
}

#[cfg(windows)]
pub fn new_journal(scopes: &[Scope]) -> Result<Journal, String> {
    use windows_sys::Win32::Security::Cryptography::{
        BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
    };
    let mut token = [0u8; 16];
    // SAFETY: valid writable buffer; system-preferred RNG requires a null algorithm.
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            token.as_mut_ptr(),
            token.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status < 0 {
        return Err("NRPT secure random generation failed".into());
    }
    let journal = Journal {
        owner: token.iter().map(|b| format!("{b:02x}")).collect(),
        scopes: scopes.to_vec(),
    };
    journal.validate()?;
    Ok(journal)
}

/// Split DNS cannot relax the full-tunnel DNS firewall guard. Until a separate
/// scoped resolver firewall policy exists, ambient/public DNS remains blocked.
pub fn require_guard(dns_guard: bool) -> Result<(), String> {
    if dns_guard {
        Ok(())
    } else {
        Err("split DNS requires the existing DNS guard; disabling it is unsupported".into())
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct Observation {
    pub owned_rules: usize,
    pub effective_scopes: usize,
}

/// Verify both local ownership and effective policy; GPO shadowing fails closed.
pub fn observe(journal: &Journal) -> Result<Observation, String> {
    invoke("observe", journal)
}

/// Idempotent recovery uses the persisted journal; a new owner must not adopt old rules.
/// Keep the tunnel/firewall in place on failure and restore using the same journal.
pub fn apply(journal: &Journal, dns_guard: bool) -> Result<Observation, String> {
    require_guard(dns_guard)?;
    invoke("apply", journal)
}

/// Refuses to delete modified rules or policy with ambiguous ownership.
pub fn restore(journal: &Journal) -> Result<Observation, String> {
    invoke("restore", journal)
}

fn invoke(action: &str, journal: &Journal) -> Result<Observation, String> {
    journal.validate()?;
    run(action, journal)
}

#[cfg(not(windows))]
fn run(_: &str, _: &Journal) -> Result<Observation, String> {
    Err("scoped NRPT DNS is unsupported on this platform".into())
}

#[cfg(windows)]
fn run(action: &str, journal: &Journal) -> Result<Observation, String> {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    // Use the system executable, never PATH resolution from a privileged service.
    let root = std::env::var_os("SystemRoot").ok_or("SystemRoot unavailable")?;
    let exe = std::path::PathBuf::from(root).join("System32/WindowsPowerShell/v1.0/powershell.exe");
    let input = serde_json::to_vec(&serde_json::json!({"action":action,"journal":journal}))
        .map_err(|_| "NRPT input serialization failed")?;
    let mut child = Command::new(exe)
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            include_str!("nrpt.ps1"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "NRPT PowerShell unavailable")?;
    let write_result = child
        .stdin
        .take()
        .ok_or("NRPT stdin unavailable")?
        .write_all(&input);
    if write_result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
        return Err("NRPT input failed".into());
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(50))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("NRPT operation timed out or could not be observed; retain journal and DNS guard".into());
            }
        }
    }
    let output = child
        .wait_with_output()
        .map_err(|_| "NRPT execution failed")?;
    if !output.status.success() {
        // Errors contain policy metadata only; don't expose arbitrary PowerShell diagnostics.
        return Err("NRPT operation failed: unsupported cmdlets, policy conflict, ownership drift, or insufficient privileges; retain journal and DNS guard".into());
    }
    serde_json::from_slice(&output.stdout).map_err(|_| "NRPT observation invalid".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    fn journal() -> Journal {
        Journal {
            owner: "0123456789abcdef0123456789abcdef".into(),
            scopes: vec![Scope {
                namespace: ".corp.example".into(),
                servers: vec![Ipv4Addr::new(10, 0, 0, 53)],
            }],
        }
    }
    #[test]
    fn rejects_injection_global_and_noncanonical_scopes() {
        for bad in [
            ".",
            "corp.example",
            ".corp.example;Remove-Item",
            ".Corp.example",
            ".a..example",
            ".-corp.example",
            ".corp.example.",
            ".*.example",
        ] {
            let mut j = journal();
            j.scopes[0].namespace = bad.into();
            assert!(j.validate().is_err(), "{bad}");
        }
        assert!(journal().validate().is_ok());
    }
    #[test]
    fn rejects_parent_child_overlap_but_accepts_siblings() {
        let mut j = journal();
        let mut s = j.scopes[0].clone();
        s.namespace = ".child.corp.example".into();
        j.scopes.push(s);
        assert!(j.validate().is_err());
        j.scopes[1].namespace = ".other.example".into();
        assert!(j.validate().is_ok());
    }
    #[test]
    fn validates_ownership_and_servers() {
        let mut j = journal();
        j.owner = "foreign".into();
        assert!(j.validate().is_err());
        for ip in [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::BROADCAST,
            Ipv4Addr::new(224, 0, 0, 1),
        ] {
            let mut j = journal();
            j.scopes[0].servers = vec![ip];
            assert!(j.validate().is_err());
        }
        let mut j = journal();
        let duplicate = j.scopes[0].servers[0];
        j.scopes[0].servers.push(duplicate);
        assert!(j.validate().is_err());
    }
    #[test]
    fn guard_cannot_be_relaxed() {
        assert!(apply(&journal(), false).is_err());
        assert!(require_guard(true).is_ok());
    }
    #[cfg(windows)]
    #[test]
    fn powershell_mock_lifecycle_preserves_foreign_and_drifted_policy() {
        let Some(root) = std::env::var_os("SystemRoot") else {
            panic!("SystemRoot unavailable");
        };
        let script = include_str!("../tests/nrpt-mock.ps1")
            .replace("__BACKEND__", &include_str!("nrpt.ps1").replace('\'', "''"));
        let output = std::process::Command::new(
            std::path::PathBuf::from(root).join("System32/WindowsPowerShell/v1.0/powershell.exe"),
        )
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &script,
        ])
        .output();
        assert!(output.is_ok(), "PowerShell unavailable");
        if let Ok(output) = output {
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("NRPT mock lifecycle passed"));
        }
    }
    /// Run elevated on an isolated Windows VM with no overlapping NRPT policy.
    /// Exercises real cmdlets; it does not claim packet-level leak protection.
    #[cfg(windows)]
    #[test]
    #[ignore = "requires elevated isolated Windows VM; modifies NRPT"]
    fn windows_nrpt_lifecycle() {
        let time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let mut j = journal();
        j.owner = format!("{time:032x}");
        j.scopes[0].namespace = format!(".lovpn-{time:x}.invalid");
        let first = apply(&j, true);
        let repeat = first.as_ref().ok().map(|_| apply(&j, true));
        let observed = observe(&j);
        // Always attempt cleanup even if installation/observation failed halfway.
        let restored = restore(&j);
        assert!(first.is_ok(), "{first:?}");
        assert!(matches!(repeat, Some(Ok(_))), "{repeat:?}");
        assert!(
            matches!(
                observed,
                Ok(Observation {
                    owned_rules: 1,
                    effective_scopes: 1
                })
            ),
            "{observed:?}"
        );
        assert!(
            matches!(restored, Ok(Observation { owned_rules: 0, .. })),
            "{restored:?}"
        );
        assert!(restore(&j).is_ok());
        assert!(observe(&j).is_err());
    }
    #[cfg(not(windows))]
    #[test]
    fn unsupported_is_explicit() {
        assert!(observe(&journal()).is_err());
        assert!(restore(&journal()).is_err());
    }
}
