//! The client broker's wire protocol: one JSON line per request and response. Shared by the
//! Unix-socket broker, the Windows named-pipe service and the CLI.
use crate::{
    ClientError,
    model::{ConnectReport, ProfileInfo, Status},
};
use lovpn_keys::ClientPublicKey;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Value, json};
use zeroize::Zeroizing;

/// A secret string that is zeroized on drop and never printed.
pub struct Secret(Zeroizing<String>);

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl serde::de::Visitor<'_> for Visitor {
            type Value = Secret;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a string")
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Secret, E> {
                Ok(Secret(Zeroizing::new(value.to_owned())))
            }
        }
        deserializer.deserialize_str(Visitor)
    }
}

impl Secret {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

/// No `Debug`: requests may carry a private key and must never be formatted.
#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Request {
    Ping,
    Status,
    ListProfiles,
    ImportProfile {
        name: String,
        profile: String,
        private_key: Secret,
        expected_server_key: String,
    },
    RemoveProfile {
        name: String,
    },
    /// Windows: create a client key pair held only by the service; returns the public key.
    GenerateIdentity {
        name: String,
    },
    /// Windows: import a profile using the identity made by `generate-identity`.
    ImportIdentityProfile {
        name: String,
        profile: String,
        expected_server_key: String,
    },
    UseProfile {
        name: String,
    },
    PublicKey {
        name: String,
    },
    Connect {
        #[serde(default)]
        profile: Option<String>,
    },
    Disconnect {
        #[serde(default)]
        release: bool,
    },
    Reconnect,
    Repair,
    Reset,
    /// Windows: the service's own log (the Linux service logs to the journal).
    Logs {
        #[serde(default)]
        lines: u32,
    },
}

impl Request {
    pub fn op(&self) -> &'static str {
        match self {
            Self::Ping => "ping",
            Self::Status => "status",
            Self::ListProfiles => "list-profiles",
            Self::ImportProfile { .. } => "import-profile",
            Self::RemoveProfile { .. } => "remove-profile",
            Self::GenerateIdentity { .. } => "generate-identity",
            Self::ImportIdentityProfile { .. } => "import-identity-profile",
            Self::UseProfile { .. } => "use-profile",
            Self::PublicKey { .. } => "public-key",
            Self::Connect { .. } => "connect",
            Self::Disconnect { .. } => "disconnect",
            Self::Reconnect => "reconnect",
            Self::Repair => "repair",
            Self::Reset => "reset",
            Self::Logs { .. } => "logs",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Response {
    pub ok: bool,
    pub code: String,
    pub message: String,
    #[serde(default)]
    pub data: Value,
}

impl Response {
    pub fn success(data: Value) -> Self {
        Self {
            ok: true,
            code: "ok".into(),
            message: "ok".into(),
            data,
        }
    }
    pub fn failure(code: &str, message: impl Into<String>) -> Self {
        Self {
            ok: false,
            code: code.into(),
            message: message.into(),
            data: Value::Null,
        }
    }
}

/// What a platform's connection engine must offer the broker. One dispatch function turns
/// requests into calls, so Linux and Windows cannot disagree about the protocol.
pub trait ClientEngine {
    fn observe(&self) -> Status;
    fn list_profiles(&self) -> Result<Vec<ProfileInfo>, ClientError>;
    fn selected_profile(&self) -> Result<Option<String>, ClientError>;
    fn use_profile(&mut self, name: &str) -> Result<(), ClientError>;
    fn import_profile(
        &mut self,
        name: &str,
        profile: &str,
        private_key: &str,
        expected_server_key: &str,
    ) -> Result<ProfileInfo, ClientError>;
    fn remove_profile(&mut self, name: &str) -> Result<(), ClientError>;
    fn public_key_of(&self, name: &str) -> Result<ClientPublicKey, ClientError>;
    fn connect(&mut self, profile: Option<&str>) -> Result<ConnectReport, ClientError>;
    fn disconnect(&mut self, release: bool) -> Result<(), ClientError>;
    fn reconnect(&mut self) -> Result<ConnectReport, ClientError>;
    fn repair(&mut self) -> Result<(), ClientError>;
    fn reset(&mut self) -> Result<(), ClientError>;
    /// Windows only: a key pair the service keeps; returns the public key.
    fn generate_identity(&mut self, _name: &str) -> Result<ClientPublicKey, ClientError> {
        Err(ClientError::UnsupportedOperation)
    }
    fn import_identity_profile(
        &mut self,
        _name: &str,
        _profile: &str,
        _expected_server_key: &str,
    ) -> Result<ProfileInfo, ClientError> {
        Err(ClientError::UnsupportedOperation)
    }
    fn logs(&self, _lines: u32) -> Result<Vec<String>, ClientError> {
        Err(ClientError::UnsupportedOperation)
    }
}

pub fn dispatch<E: ClientEngine>(engine: &mut E, request: Request) -> Response {
    let result: Result<Value, ClientError> = match request {
        Request::Ping => Ok(json!({"pong": true})),
        Request::Status => Ok(json!(engine.observe())),
        Request::ListProfiles => engine
            .list_profiles()
            .and_then(|p| Ok(json!({"profiles": p, "selected": engine.selected_profile()?}))),
        Request::UseProfile { name } => engine.use_profile(&name).map(|()| json!({})),
        Request::ImportProfile {
            name,
            profile,
            private_key,
            expected_server_key,
        } => engine
            .import_profile(&name, &profile, private_key.expose(), &expected_server_key)
            .map(|info| json!({"profile": info})),
        Request::RemoveProfile { name } => engine.remove_profile(&name).map(|()| json!({})),
        Request::GenerateIdentity { name } => engine
            .generate_identity(&name)
            .map(|key| json!({"public_key": key.to_string()})),
        Request::ImportIdentityProfile {
            name,
            profile,
            expected_server_key,
        } => engine
            .import_identity_profile(&name, &profile, &expected_server_key)
            .map(|info| json!({"profile": info})),
        Request::PublicKey { name } => engine
            .public_key_of(&name)
            .map(|key| json!({"public_key": key.to_string()})),
        Request::Connect { profile } => engine.connect(profile.as_deref()).map(|r| json!(r)),
        Request::Disconnect { release } => engine.disconnect(release).map(|()| json!({})),
        Request::Reconnect => engine.reconnect().map(|r| json!(r)),
        Request::Repair => engine.repair().map(|()| json!({})),
        Request::Reset => engine.reset().map(|()| json!({})),
        Request::Logs { lines } => engine.logs(lines).map(|l| json!({"lines": l})),
    };
    match result {
        Ok(data) => Response::success(data),
        Err(error) => Response::failure(error.code(), error.to_string()),
    }
}
