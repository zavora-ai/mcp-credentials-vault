use adk_mcp_sdk::{HealthCheck, HealthStatus};
use std::sync::Arc;

use rmcp::{handler::server::wrapper::Parameters, schemars, tool, tool_router};
use serde::{Deserialize, Serialize};

use crate::backend::VaultBackend;
use crate::types::*;

/// The Credentials Vault MCP server.
#[derive(Clone)]
pub struct CredentialsVaultServer {
    backends: Arc<Vec<Box<dyn VaultBackend>>>,
}

impl CredentialsVaultServer {
    pub fn new(backends: Vec<Box<dyn VaultBackend>>) -> Self {
        Self {
            backends: Arc::new(backends),
        }
    }

    async fn find_backend_for(&self, credential_id: &str) -> Option<&dyn VaultBackend> {
        for backend in self.backends.iter() {
            if backend.get_credential(credential_id).await.is_ok() {
                return Some(backend.as_ref());
            }
        }
        None
    }
}

// --- Tool input types ---

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct ListCredentialsInput {
    #[serde(default)]
    pub backend: Option<String>,
    #[serde(default)]
    pub owner: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct GetCredentialMetadataInput {
    pub credential_id: String,
}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct RequestRuntimeSecretInput {
    pub credential_id: String,
    #[serde(default)]
    pub scope: Vec<String>,
    #[serde(default)]
    pub ttl_seconds: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct RequestWorkloadTokenInput {
    pub credential_id: String,
    pub audience: String,
    #[serde(default)]
    pub ttl_seconds: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct RotateCredentialInput {
    pub credential_id: String,
}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct RevokeCredentialInput {
    pub credential_id: String,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct AuditCredentialAccessInput {
    #[serde(default)]
    pub credential_id: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct ValidateSecretScopeInput {
    pub credential_id: String,
    pub actor: String,
}

// --- MCP Tool implementations ---

#[tool_router(server_handler)]
impl CredentialsVaultServer {
    #[tool(description = "List credential metadata — never exposes raw secret values")]
    async fn list_credentials(
        &self,
        Parameters(input): Parameters<ListCredentialsInput>,
    ) -> String {
        let mut all_creds = Vec::new();
        for backend in self.backends.iter() {
            if let Ok(creds) = backend.list_credentials().await {
                all_creds.extend(creds);
            }
        }

        if let Some(ref backend_filter) = input.backend {
            all_creds.retain(|c| {
                serde_json::to_string(&c.backend)
                    .unwrap_or_default()
                    .contains(backend_filter)
            });
        }
        if let Some(ref owner_filter) = input.owner {
            all_creds.retain(|c| c.owner.contains(owner_filter));
        }

        let handles: Vec<CredentialHandle> = all_creds.iter().map(CredentialHandle::from).collect();
        serde_json::to_string_pretty(&handles).unwrap_or_else(|e| format!("Error: {}", e))
    }

    #[tool(description = "Inspect owner, scope, expiry, rotation policy, and risk level")]
    async fn get_credential_metadata(
        &self,
        Parameters(input): Parameters<GetCredentialMetadataInput>,
    ) -> String {
        match self.find_backend_for(&input.credential_id).await {
            Some(backend) => match backend.get_credential(&input.credential_id).await {
                Ok(cred) => {
                    let handle = CredentialHandle::from(&cred);
                    serde_json::to_string_pretty(&handle)
                        .unwrap_or_else(|e| format!("Error: {}", e))
                }
                Err(e) => format!("Error: {}", e),
            },
            None => format!("Credential not found: {}", input.credential_id),
        }
    }

    #[tool(description = "Issue a scoped runtime handle after policy checks — returns handle, not raw secret")]
    async fn request_runtime_secret(
        &self,
        Parameters(input): Parameters<RequestRuntimeSecretInput>,
    ) -> String {
        let ttl = input.ttl_seconds.unwrap_or(300);
        match self.find_backend_for(&input.credential_id).await {
            Some(backend) => {
                match backend
                    .issue_runtime_handle(&input.credential_id, &input.scope, ttl)
                    .await
                {
                    Ok(handle) => serde_json::to_string_pretty(&handle)
                        .unwrap_or_else(|e| format!("Error: {}", e)),
                    Err(e) => format!("Error: {}", e),
                }
            }
            None => format!("Credential not found: {}", input.credential_id),
        }
    }

    #[tool(description = "Mint a short-lived OIDC or workload identity token")]
    async fn request_workload_token(
        &self,
        Parameters(input): Parameters<RequestWorkloadTokenInput>,
    ) -> String {
        let ttl = input.ttl_seconds.unwrap_or(3600);
        match self.find_backend_for(&input.credential_id).await {
            Some(backend) => {
                match backend
                    .mint_workload_token(&input.credential_id, &input.audience, ttl)
                    .await
                {
                    Ok(token) => serde_json::to_string_pretty(&token)
                        .unwrap_or_else(|e| format!("Error: {}", e)),
                    Err(e) => format!("Error: {}", e),
                }
            }
            None => format!("Credential not found: {}", input.credential_id),
        }
    }

    #[tool(description = "Rotate a secret through the approved workflow")]
    async fn rotate_credential(
        &self,
        Parameters(input): Parameters<RotateCredentialInput>,
    ) -> String {
        match self.find_backend_for(&input.credential_id).await {
            Some(backend) => match backend.rotate(&input.credential_id).await {
                Ok(()) => format!("Credential {} rotated successfully", input.credential_id),
                Err(e) => format!("Rotation failed: {}", e),
            },
            None => format!("Credential not found: {}", input.credential_id),
        }
    }

    #[tool(description = "Disable a compromised or expired credential")]
    async fn revoke_credential(
        &self,
        Parameters(input): Parameters<RevokeCredentialInput>,
    ) -> String {
        match self.find_backend_for(&input.credential_id).await {
            Some(backend) => match backend.revoke(&input.credential_id).await {
                Ok(()) => format!(
                    "Credential {} revoked{}",
                    input.credential_id,
                    input
                        .reason
                        .map(|r| format!(" (reason: {})", r))
                        .unwrap_or_default()
                ),
                Err(e) => format!("Revocation failed: {}", e),
            },
            None => format!("Credential not found: {}", input.credential_id),
        }
    }

    #[tool(description = "Retrieve access, denial, and rotation audit events")]
    async fn audit_credential_access(
        &self,
        Parameters(input): Parameters<AuditCredentialAccessInput>,
    ) -> String {
        let limit = input.limit.unwrap_or(50);
        let mut all_events = Vec::new();

        for backend in self.backends.iter() {
            if let Ok(events) = backend.audit_log(input.credential_id.as_deref(), limit).await {
                all_events.extend(events);
            }
        }

        all_events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        all_events.truncate(limit);
        serde_json::to_string_pretty(&all_events).unwrap_or_else(|e| format!("Error: {}", e))
    }

    #[tool(description = "Check whether an agent, skill, or MCP server can use a credential")]
    async fn validate_secret_scope(
        &self,
        Parameters(input): Parameters<ValidateSecretScopeInput>,
    ) -> String {
        match self.find_backend_for(&input.credential_id).await {
            Some(backend) => match backend.get_credential(&input.credential_id).await {
                Ok(cred) => {
                    let allowed = cred.scope.is_empty() || cred.scope.contains(&input.actor);
                    let result = serde_json::json!({
                        "credential_id": input.credential_id,
                        "actor": input.actor,
                        "allowed": allowed,
                        "scope": cred.scope,
                        "status": cred.status,
                    });
                    serde_json::to_string_pretty(&result)
                        .unwrap_or_else(|e| format!("Error: {}", e))
                }
                Err(e) => format!("Error: {}", e),
            },
            None => format!("Credential not found: {}", input.credential_id),
        }
    }
}

#[async_trait::async_trait]
impl HealthCheck for CredentialsVaultServer {
    async fn check_health(&self) -> HealthStatus {
        HealthStatus {
            healthy: true,
            message: Some("operational".into()),
            latency_ms: Some(1),
        }
    }
}
