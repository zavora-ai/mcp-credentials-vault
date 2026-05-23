//! # Credentials Vault MCP Server
//!
//! Provides scoped, auditable credential access for ADK-Rust Enterprise agents.
//! No raw secrets are ever exposed to LLM context.

pub mod backend;
pub mod error;
pub mod types;

#[cfg(feature = "hashicorp")]
pub mod hashicorp;

#[cfg(feature = "aws")]
pub mod aws;

#[cfg(feature = "gcp")]
pub mod gcp;

#[cfg(feature = "azure")]
pub mod azure;

#[cfg(feature = "adk-vault")]
pub mod adk_vault;

#[cfg(feature = "adk-platform")]
pub mod adk_platform;

pub mod server;

pub use backend::VaultBackend;
pub use error::VaultError;
pub use types::*;
