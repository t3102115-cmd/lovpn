use std::{error::Error, fmt};

/// Static, sanitized errors: never contain keys, tokens, paths or OS error text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerError {
    Name,
    Label,
    Interface,
    Endpoint,
    Pool,
    Dns,
    Mtu,
    Ipv6,
    Key,
    KeyLooksPrivate,
    DuplicateKey,
    DuplicateName,
    NotFound,
    PoolExhausted,
    TooManyPeers,
    Revoked,
    State,
    Version,
    Generation,
    Busy,
    Storage,
    Permissions,
    Exists,
    Export,
    Unsupported,
}

impl ServerError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Name => "server.peer-name",
            Self::Label => "server.label",
            Self::Interface => "server.interface",
            Self::Endpoint => "server.endpoint",
            Self::Pool => "server.pool",
            Self::Dns => "server.dns",
            Self::Mtu => "server.mtu",
            Self::Ipv6 => "server.ipv6",
            Self::Key => "server.key",
            Self::KeyLooksPrivate => "server.key-looks-private",
            Self::DuplicateKey => "server.duplicate-key",
            Self::DuplicateName => "server.duplicate-name",
            Self::NotFound => "server.peer-not-found",
            Self::PoolExhausted => "server.pool-exhausted",
            Self::TooManyPeers => "server.too-many-peers",
            Self::Revoked => "server.peer-revoked",
            Self::State => "state.invalid",
            Self::Version => "state.version",
            Self::Generation => "state.generation-conflict",
            Self::Busy => "state.busy",
            Self::Storage => "state.storage",
            Self::Permissions => "state.permissions",
            Self::Exists => "state.exists",
            Self::Export => "server.export",
            Self::Unsupported => "server.unsupported",
        }
    }
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Name => "Peer name must be 1–64 bytes of letters, numbers, '-', '_' or '.', not all digits.",
            Self::Label => "Server label must be 1–80 bytes of letters, numbers, spaces or -_.(), without surrounding spaces.",
            Self::Interface => "Interface names must be 1–15 ASCII letters, digits, '_', '-' or '.'; the tunnel interface must differ from the uplink.",
            Self::Endpoint => "Public endpoint must be a literal unicast IP address and nonzero port that produces a valid client profile.",
            Self::Pool => "Address pool must be a canonical private IPv4 network (10/8, 172.16/12, 192.168/16 or 100.64/10) from /16 to /29.",
            Self::Dns => "Provide 1–4 DNS resolver IPs that clients can reach through the tunnel. LoVPN does not run a resolver.",
            Self::Mtu => "MTU must be from 1280 to 1420.",
            Self::Ipv6 => "Only the explicit IPv6 'block' policy is implemented in this version.",
            Self::Key => "Client public key must be a canonical, non-weak WireGuard key that differs from the server's.",
            Self::KeyLooksPrivate => "This value has the shape of a clamped PRIVATE key (1 in 16 genuine public keys do too). If it is the output of `lovpn identity public`, repeat with --confirm-public-key; otherwise never paste private keys.",
            Self::DuplicateKey => "That public key is, or once was, used by a peer. Generate a fresh client key.",
            Self::DuplicateName => "An active peer already uses that name.",
            Self::NotFound => "No active peer matches that name or id.",
            Self::PoolExhausted => "No free address remains in the pool. Revoked leases are quarantined, not reused.",
            Self::TooManyPeers => "Peer limit reached (1024 including revoked peers).",
            Self::Revoked => "That peer is revoked.",
            Self::State => "Server state is invalid or corrupt; nothing was changed. Restore the state directory from backup.",
            Self::Version => "Server state schema is not supported by this build (no automatic migration or downgrade).",
            Self::Generation => "The state changed since the expected generation; reload and retry.",
            Self::Busy => "Another LoVPN server operation holds the state lock; retry.",
            Self::Storage => "State storage input/output failed; the previous state remains intact.",
            Self::Permissions => "State directory must be mode 0700 and owned by the current user; files must be mode 0600 without links.",
            Self::Exists => "Server state already exists; LoVPN will not overwrite it or its identity key.",
            Self::Export => "The generated client profile failed validation; nothing was exported.",
            Self::Unsupported => "This operation is not implemented in this build.",
        })
    }
}

impl Error for ServerError {}
