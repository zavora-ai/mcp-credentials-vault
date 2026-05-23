use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Credential status in the vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialStatus {
    Active,
    Expired,
    Revoked,
    Rotating,
}

/// How often a credential should be rotated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationPolicy {
    pub interval_days: u32,
    pub auto_rotate: bool,
    pub notify_before_days: Option<u32>,
}

/// Which vault backend stores this credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendType {
    Hashicorp,
    Aws,
    Gcp,
    Azure,
    AdkVault,
}

/// Full credential record (internal — never sent to LLM context).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub id: String,
    pub display_name: String,
    pub owner: String,
    pub scope: Vec<String>,
    pub backend: BackendType,
    pub risk_level: adk_mcp_sdk::risk::RiskLevel,
    pub rotation_policy: Option<RotationPolicy>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_rotated: Option<DateTime<Utc>>,
    pub last_accessed: Option<DateTime<Utc>>,
    pub status: CredentialStatus,
    pub tags: Vec<String>,
}

/// Safe handle returned to agents — no secret value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialHandle {
    pub id: String,
    pub display_name: String,
    pub status: CredentialStatus,
    pub owner: String,
    pub scope: Vec<String>,
    pub backend: BackendType,
    pub risk_level: adk_mcp_sdk::risk::RiskLevel,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_rotated: Option<DateTime<Utc>>,
    pub rotation_policy: Option<RotationPolicy>,
}

impl From<&Credential> for CredentialHandle {
    fn from(c: &Credential) -> Self {
        Self {
            id: c.id.clone(),
            display_name: c.display_name.clone(),
            status: c.status,
            owner: c.owner.clone(),
            scope: c.scope.clone(),
            backend: c.backend.clone(),
            risk_level: c.risk_level,
            expires_at: c.expires_at,
            last_rotated: c.last_rotated,
            rotation_policy: c.rotation_policy.clone(),
        }
    }
}

/// A runtime secret handle — the actual secret is resolved by the runtime worker,
/// never exposed in LLM context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeSecretHandle {
    pub handle_id: String,
    pub credential_id: String,
    pub expires_at: DateTime<Utc>,
    pub scope: Vec<String>,
}

/// A minted workload identity token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkloadToken {
    pub token_id: String,
    pub credential_id: String,
    pub token_type: String,
    pub expires_at: DateTime<Utc>,
    pub audience: String,
}

/// Audit event for credential access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub event_id: String,
    pub credential_id: String,
    pub action: AuditAction,
    pub actor: String,
    pub timestamp: DateTime<Utc>,
    pub outcome: AuditOutcome,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    Access,
    Denied,
    Rotated,
    Revoked,
    TokenMinted,
    ScopeValidated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    Success,
    Denied,
    Error,
}
