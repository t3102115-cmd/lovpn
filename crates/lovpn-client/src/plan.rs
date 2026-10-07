//! Pure planning for the client: what the kernel must look like, derived only from a
//! validated profile. No I/O, so it is testable without privileges.
use crate::ClientError;
use lovpn_config::{ClientConfig, Ipv6Mode, RoutingMode};
use lovpn_firewall::WIREGUARD_FWMARK;
use lovpn_keys::ClientPrivateKey;
use zeroize::Zeroizing;

/// Policy-routing table holding the tunnel default route. Same number as the fwmark.
pub fn route_table() -> String {
    WIREGUARD_FWMARK.to_string()
}

pub fn fwmark_hex() -> String {
    format!("{WIREGUARD_FWMARK:#x}")
}

/// `ip rule` priorities reserved for LoVPN. Unmarked traffic is sent to the tunnel table;
/// if that table has no route (tunnel down) the next rule makes the lookup fail instead of
/// falling through to the main table: routing itself fails closed.
pub const RULE_LOOKUP_PRIORITY: u64 = 9100;
pub const RULE_BLOCK_PRIORITY: u64 = 9101;
pub const KEEPALIVE_SECS: u32 = 25;

/// Reject profiles this client cannot enforce *and verify* yet, instead of half-applying.
pub fn check_supported(config: &ClientConfig) -> Result<(), ClientError> {
    #[cfg(not(windows))]
    if !config.dns.scopes.is_empty() {
        return Err(ClientError::UnsupportedOperation);
    }
    if config.tunnel.routing != RoutingMode::Full {
        return Err(ClientError::UnsupportedRouting);
    }
    if config.tunnel.ipv6 != Ipv6Mode::Block {
        return Err(ClientError::UnsupportedIpv6Tunnel);
    }
    if config.profile.endpoint.is_ipv6() {
        return Err(ClientError::UnsupportedEndpoint);
    }
    Ok(())
}

/// WireGuard configuration for `wg syncconf`. Contains the private key, so it is passed
/// to `wg` only through standard input and zeroized afterwards.
pub fn wireguard_config(config: &ClientConfig, key: &ClientPrivateKey) -> Zeroizing<String> {
    let mut text = Zeroizing::new(String::new());
    text.push_str("[Interface]\nPrivateKey = ");
    text.push_str(&key.expose_base64());
    text.push_str(&format!("\nFwMark = {}\n", fwmark_hex()));
    text.push_str(&format!(
        "\n[Peer]\nPublicKey = {}\nEndpoint = {}\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = {KEEPALIVE_SECS}\n",
        config.profile.server_public_key, config.profile.endpoint
    ));
    text
}

/// The tunnel address that must be on the interface, as `ip addr` wants it.
pub fn tunnel_addresses(config: &ClientConfig) -> Vec<String> {
    config
        .tunnel
        .addresses
        .iter()
        .filter(|a| a.addr().is_ipv4())
        .map(|a| format!("{}/{}", a.addr(), a.prefix_len()))
        .collect()
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;
    #[test]
    fn scoped_dns_is_rejected_even_with_full_tunnel_and_valid_baseline() {
        let text = include_str!("../../../examples/client.toml");
        let baseline = lovpn_config::parse(text);
        assert!(baseline.is_ok());
        if let Ok(config) = baseline {
            assert!(check_supported(&config).is_ok());
        }
        let scoped = text.replace(
            "[dns]",
            "[dns]\nscopes = [{ namespace = \".corp.example\", servers = [\"10.66.0.53\"] }]",
        );
        let config = lovpn_config::parse(&scoped);
        assert!(config.is_ok());
        if let Ok(config) = config {
            assert_eq!(
                check_supported(&config),
                Err(ClientError::UnsupportedOperation)
            );
        }
    }
}
