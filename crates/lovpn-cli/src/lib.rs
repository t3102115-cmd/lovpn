//! LoVPN command-line client as a library: the same operations back the `lovpn` command
//! and the `lovpn-ui` window, so the two cannot disagree about what is true.
use serde_json::Value;

pub mod client;
pub mod enroll;
pub mod input;
pub mod reports;

#[derive(Debug)]
pub struct AppError {
    pub code: String,
    pub message: String,
}

impl AppError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

impl From<lovpn_config::ConfigError> for AppError {
    fn from(error: lovpn_config::ConfigError) -> Self {
        Self::new(error.code(), error.to_string())
    }
}

impl From<lovpn_firewall::FirewallError> for AppError {
    fn from(error: lovpn_firewall::FirewallError) -> Self {
        Self::new(error.code(), error.to_string())
    }
}

pub struct Report {
    pub data: Value,
    pub text: String,
}
