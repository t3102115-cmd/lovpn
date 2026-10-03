use crate::{ClientConfig, ConfigError, Ipv6Mode, RoutingMode, SCHEMA_VERSION};
use base64::{Engine, engine::general_purpose::STANDARD};
use ipnet::IpNet;
use std::net::{IpAddr, SocketAddr};

impl ClientConfig {
    /// Revalidate even manually constructed or changed configurations.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ConfigError::Version);
        }
        let name = &self.profile.name;
        if name.is_empty()
            || name.len() > 80
            || name.trim() != name
            || !name
                .chars()
                .all(|c| c.is_alphanumeric() || " -_.()".contains(c))
        {
            return Err(ConfigError::Name);
        }
        let endpoint = self.profile.endpoint;
        if endpoint.port() == 0
            || !is_unicast(endpoint.ip())
            || matches!(endpoint, SocketAddr::V6(v6) if v6.scope_id() != 0 || v6.flowinfo() != 0)
        {
            return Err(ConfigError::Endpoint);
        }
        let key = &self.profile.server_public_key;
        if key.len() != 44 {
            return Err(ConfigError::PublicKey);
        }
        let decoded = STANDARD.decode(key).map_err(|_| ConfigError::PublicKey)?;
        if decoded.len() != 32
            || decoded.iter().all(|byte| *byte == 0)
            || STANDARD.encode(&decoded) != *key
        {
            return Err(ConfigError::PublicKey);
        }
        let interface = &self.tunnel.interface;
        if !interface.starts_with("lovpn")
            || interface.len() > 15
            || !interface
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
        {
            return Err(ConfigError::Interface);
        }
        if !(1280..=1420).contains(&self.tunnel.mtu) {
            return Err(ConfigError::Mtu);
        }
        self.validate_addresses()?;
        self.validate_routes()?;
        self.validate_dns()
    }

    fn validate_addresses(&self) -> Result<(), ConfigError> {
        let addresses = &self.tunnel.addresses;
        if addresses.is_empty() || addresses.len() > 8 {
            return Err(ConfigError::Addresses);
        }
        for (index, address) in addresses.iter().enumerate() {
            if !is_unicast(address.addr())
                || addresses[..index]
                    .iter()
                    .any(|other| other.addr() == address.addr())
                || matches!(address, IpNet::V4(v4) if v4.prefix_len() < 31 && (v4.addr() == v4.network() || v4.addr() == v4.broadcast()))
            {
                return Err(ConfigError::Addresses);
            }
        }
        if !addresses.iter().any(|address| address.addr().is_ipv4()) {
            return Err(ConfigError::Addresses);
        }
        let has_ipv6 = addresses.iter().any(|address| address.addr().is_ipv6());
        if has_ipv6 != (self.tunnel.ipv6 == Ipv6Mode::Tunnel) {
            return Err(ConfigError::Ipv6Policy);
        }
        Ok(())
    }

    fn validate_routes(&self) -> Result<(), ConfigError> {
        let routes = &self.tunnel.routes;
        if routes.is_empty() || routes.len() > 64 {
            return Err(ConfigError::Routes);
        }
        for (index, route) in routes.iter().enumerate() {
            if route.addr() != route.network()
                || routes[..index].iter().any(|other| overlaps(*route, *other))
            {
                return Err(ConfigError::Routes);
            }
            if route.addr().is_ipv6() && self.tunnel.ipv6 == Ipv6Mode::Block {
                return Err(ConfigError::Ipv6Policy);
            }
        }
        match self.tunnel.routing {
            RoutingMode::Full => {
                let expected = if self.tunnel.ipv6 == Ipv6Mode::Tunnel {
                    2
                } else {
                    1
                };
                if routes.len() != expected
                    || !routes
                        .iter()
                        .any(|r| r.addr().is_ipv4() && r.prefix_len() == 0)
                    || routes.iter().any(|r| r.prefix_len() != 0)
                {
                    return Err(ConfigError::Routes);
                }
            }
            RoutingMode::Split => {
                // Reject routes intersecting local/multicast/reserved ranges.
                // Static constants are parsed fallibly, without unchecked assumptions.
                const SPECIAL: &[&str] = &[
                    "0.0.0.0/8",
                    "127.0.0.0/8",
                    "169.254.0.0/16",
                    "224.0.0.0/3",
                    "::/96",
                    "::ffff:0:0/96",
                    "fe80::/10",
                    "ff00::/8",
                ];
                for route in routes {
                    if route.prefix_len() == 0 {
                        return Err(ConfigError::Routes);
                    }
                    for reserved in SPECIAL {
                        let reserved = reserved.parse().map_err(|_| ConfigError::Routes)?;
                        if overlaps(*route, reserved) {
                            return Err(ConfigError::Routes);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn validate_dns(&self) -> Result<(), ConfigError> {
        let servers = &self.dns.servers;
        if servers.is_empty() || servers.len() > 4 {
            return Err(ConfigError::Dns);
        }
        for (index, server) in servers.iter().enumerate() {
            if !is_unicast(*server)
                || servers[..index].contains(server)
                || (server.is_ipv6() && self.tunnel.ipv6 == Ipv6Mode::Block)
            {
                return Err(ConfigError::Dns);
            }
            if !self
                .tunnel
                .routes
                .iter()
                .any(|route| route.contains(server))
            {
                return Err(ConfigError::DnsRoute);
            }
        }
        Ok(())
    }
}

fn overlaps(first: IpNet, second: IpNet) -> bool {
    first.contains(&second.addr()) || second.contains(&first.addr())
}

fn is_unicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let first = v4.octets()[0];
            first != 0 && first < 224 && !v4.is_loopback() && !v4.is_link_local()
        }
        IpAddr::V6(v6) => {
            !v6.is_unspecified()
                && !v6.is_loopback()
                && !v6.is_multicast()
                && !v6.is_unicast_link_local()
                && v6.to_ipv4().is_none()
        }
    }
}
