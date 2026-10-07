//! Online-enrollment state: one-time tokens kept *inside* [`ServerState`], so creating
//! the peer and consuming the token are one atomic, generation-checked commit
//! (`Store::update`). A crash leaves either both or neither.
//!
//! Only a SHA-256 digest of each token secret is stored, never the token. Redemption
//! is single-use and bound to the first client key; a repeat with the same token and
//! same key inside [`REPLAY_WINDOW`] re-delivers the same peer (lost response), any
//! other repeat is refused. Time that moves backwards beyond [`CLOCK_TOLERANCE`]
//! relative to the persisted high-water mark is refused, never silently extended.
use crate::{Peer, ServerError, ServerState};
use lovpn_enroll::token::{self, Token};
use lovpn_keys::ClientPublicKey;
use serde::{Deserialize, Serialize};

pub const MAX_TOKENS: usize = 256;
pub const DEFAULT_TTL: u64 = 15 * 60;
pub const MAX_TTL: u64 = 24 * 60 * 60;
/// How long after redemption an identical retry still receives the same profile.
pub const REPLAY_WINDOW: u64 = 10 * 60;
/// Allowed backwards clock step relative to the persisted high-water mark.
pub const CLOCK_TOLERANCE: u64 = 120;
const KEEP_FINISHED: u64 = 30 * 24 * 60 * 60;
const KEEP_EXPIRED: u64 = 24 * 60 * 60;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentState {
    #[serde(default)]
    pub tokens: Vec<TokenRecord>,
    /// Highest time this state has ever been written at.
    #[serde(default)]
    pub clock_high_water: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TokenRecord {
    /// Non-secret handle (16 lowercase hex digits), safe to list and log.
    pub id: String,
    /// SHA-256 digest of the token secret (64 hex digits).
    pub digest: String,
    /// Name the peer will get; chosen by the administrator, not by the client.
    pub peer_name: String,
    pub created_unix: u64,
    pub expires_unix: u64,
    pub status: TokenStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum TokenStatus {
    Pending,
    Redeemed {
        client_public_key: String,
        peer_id: u32,
        redeemed_unix: u64,
    },
    Revoked {
        revoked_unix: u64,
    },
}

/// What a successful redemption produced.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Redemption {
    pub peer_id: u32,
    /// True when no state changed because this was an identical retry.
    pub replayed: bool,
}

impl EnrollmentState {
    pub(crate) fn validate(&self, state: &ServerState) -> Result<(), ServerError> {
        if self.tokens.len() > MAX_TOKENS {
            return Err(ServerError::State);
        }
        for (index, record) in self.tokens.iter().enumerate() {
            if !token::valid_id(&record.id)
                || token::parse_digest(&record.digest).is_none()
                || self.tokens[..index]
                    .iter()
                    .any(|other| other.id == record.id)
                || !crate::state::valid_peer_name(&record.peer_name)
                || record.expires_unix <= record.created_unix
                || record.expires_unix - record.created_unix > MAX_TTL
            {
                return Err(ServerError::State);
            }
            if let TokenStatus::Redeemed {
                client_public_key,
                peer_id,
                ..
            } = &record.status
            {
                let peer = state.peers.iter().find(|p| p.id == *peer_id);
                let key_ok = client_public_key.parse::<ClientPublicKey>().is_ok();
                if peer.is_none() || !key_ok {
                    return Err(ServerError::State);
                }
            }
        }
        Ok(())
    }
}

/// Public listing row: never contains the token or its digest.
#[derive(Clone, Debug)]
pub struct TokenInfo {
    pub id: String,
    pub peer_name: String,
    pub status: &'static str,
    pub created_unix: u64,
    pub expires_unix: u64,
    pub peer_id: Option<u32>,
}

impl ServerState {
    fn check_clock(&mut self, now: u64) -> Result<(), ServerError> {
        let high = self.enrollment.clock_high_water;
        if now.saturating_add(CLOCK_TOLERANCE) < high {
            return Err(ServerError::Clock);
        }
        self.enrollment.clock_high_water = high.max(now);
        Ok(())
    }

    /// Create a token record for `token` (the caller shows the text once). The peer
    /// does not exist until redemption.
    pub fn issue_token(
        &mut self,
        token: &Token,
        peer_name: &str,
        ttl_secs: u64,
        now: u64,
    ) -> Result<TokenInfo, ServerError> {
        if !crate::state::valid_peer_name(peer_name) {
            return Err(ServerError::Name);
        }
        if ttl_secs == 0 || ttl_secs > MAX_TTL {
            return Err(ServerError::Ttl);
        }
        self.check_clock(now)?;
        if self
            .peers
            .iter()
            .any(|p| p.status == crate::PeerStatus::Active && p.name == peer_name)
        {
            return Err(ServerError::DuplicateName);
        }
        let tokens = &mut self.enrollment.tokens;
        tokens.retain(|r| match &r.status {
            TokenStatus::Pending => now < r.expires_unix.saturating_add(KEEP_EXPIRED),
            TokenStatus::Revoked { revoked_unix } => {
                now < revoked_unix.saturating_add(KEEP_EXPIRED)
            }
            TokenStatus::Redeemed { redeemed_unix, .. } => {
                now < redeemed_unix.saturating_add(KEEP_FINISHED)
            }
        });
        if tokens.iter().any(|r| {
            r.status == TokenStatus::Pending && now < r.expires_unix && r.peer_name == peer_name
        }) {
            return Err(ServerError::DuplicateName);
        }
        if tokens.len() >= MAX_TOKENS {
            return Err(ServerError::TokenLimit);
        }
        let record = TokenRecord {
            id: token.id_hex(),
            digest: token::digest_hex(&token.digest()),
            peer_name: peer_name.into(),
            created_unix: now,
            expires_unix: now.saturating_add(ttl_secs),
            status: TokenStatus::Pending,
        };
        let info = describe(&record, now);
        tokens.push(record);
        Ok(info)
    }

    pub fn revoke_token(&mut self, id: &str, now: u64) -> Result<(), ServerError> {
        self.check_clock(now)?;
        let record = self
            .enrollment
            .tokens
            .iter_mut()
            .find(|r| r.id == id)
            .ok_or(ServerError::TokenNotFound)?;
        match record.status {
            TokenStatus::Pending => {
                record.status = TokenStatus::Revoked { revoked_unix: now };
                Ok(())
            }
            _ => Err(ServerError::TokenState),
        }
    }

    pub fn list_tokens(&self, now: u64) -> Vec<TokenInfo> {
        self.enrollment
            .tokens
            .iter()
            .map(|r| describe(r, now))
            .collect()
    }

    /// Read-only: if `token` was already redeemed by exactly `key` inside the replay
    /// window and that peer is still active with that key, return it.
    pub fn replayed_peer(&self, token: &Token, key: &ClientPublicKey, now: u64) -> Option<&Peer> {
        let record = self
            .enrollment
            .tokens
            .iter()
            .find(|r| r.id == token.id_hex())?;
        let digest = token::parse_digest(&record.digest)?;
        if !token.matches(&digest) {
            return None;
        }
        let TokenStatus::Redeemed {
            client_public_key,
            peer_id,
            redeemed_unix,
        } = &record.status
        else {
            return None;
        };
        if *client_public_key != key.to_string()
            || now < *redeemed_unix
            || now - *redeemed_unix > REPLAY_WINDOW
        {
            return None;
        }
        self.peers.iter().find(|p| {
            p.id == *peer_id
                && p.status == crate::PeerStatus::Active
                && p.public_key == *client_public_key
        })
    }

    /// Consume `token`, creating the peer. Every refusal that a caller could use to
    /// learn about a token (unknown, wrong secret, expired, used, revoked) is the
    /// same [`ServerError::Denied`].
    pub fn redeem_token(
        &mut self,
        token: &Token,
        key: ClientPublicKey,
        now: u64,
    ) -> Result<Redemption, ServerError> {
        if let Some(peer) = self.replayed_peer(token, &key, now) {
            return Ok(Redemption {
                peer_id: peer.id,
                replayed: true,
            });
        }
        self.check_clock(now)?;
        let index = self
            .enrollment
            .tokens
            .iter()
            .position(|r| r.id == token.id_hex());
        // Compare against a dummy digest when the id is unknown so that unknown and
        // wrong-secret tokens take the same path.
        let stored = index
            .and_then(|i| token::parse_digest(&self.enrollment.tokens[i].digest))
            .unwrap_or([0u8; 32]);
        let secret_ok = token.matches(&stored);
        let Some(index) = index.filter(|_| secret_ok) else {
            return Err(ServerError::Denied);
        };
        let record = &self.enrollment.tokens[index];
        if record.status != TokenStatus::Pending || now >= record.expires_unix {
            return Err(ServerError::Denied);
        }
        let name = record.peer_name.clone();
        let key_text = key.to_string();
        let peer_id = self.create_peer(&name, key, now)?.id;
        self.enrollment.tokens[index].status = TokenStatus::Redeemed {
            client_public_key: key_text,
            peer_id,
            redeemed_unix: now,
        };
        Ok(Redemption {
            peer_id,
            replayed: false,
        })
    }
}

fn describe(record: &TokenRecord, now: u64) -> TokenInfo {
    let (status, peer_id) = match &record.status {
        TokenStatus::Pending if now >= record.expires_unix => ("expired", None),
        TokenStatus::Pending => ("pending", None),
        TokenStatus::Redeemed { peer_id, .. } => ("redeemed", Some(*peer_id)),
        TokenStatus::Revoked { .. } => ("revoked", None),
    };
    TokenInfo {
        id: record.id.clone(),
        peer_name: record.peer_name.clone(),
        status,
        created_unix: record.created_unix,
        expires_unix: record.expires_unix,
        peer_id,
    }
}
