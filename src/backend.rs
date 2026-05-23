use crate::error::VaultError;
use crate::types::{AuditEvent, Credential, RuntimeSecretHandle, WorkloadToken};

/// Trait that each vault backend implements.
#[async_trait::async_trait]
pub trait VaultBackend: Send + Sync {
    /// Backend identifier.
    fn backend_type(&self) -> crate::types::BackendType;

    /// Check connectivity and auth.
    async fn health_check(&self) -> Result<(), VaultError>;

    /// List all credentials this backend manages.
    async fn list_credentials(&self) -> Result<Vec<Credential>, VaultError>;

    /// Get a single credential by ID.
    async fn get_credential(&self, id: &str) -> Result<Credential, VaultError>;

    /// Issue a short-lived runtime handle (the backend resolves the actual secret
    /// and returns only a handle reference).
    async fn issue_runtime_handle(
        &self,
        credential_id: &str,
        scope: &[String],
        ttl_seconds: u64,
    ) -> Result<RuntimeSecretHandle, VaultError>;

    /// Mint a workload identity token (OIDC/JWT).
    async fn mint_workload_token(
        &self,
        credential_id: &str,
        audience: &str,
        ttl_seconds: u64,
    ) -> Result<WorkloadToken, VaultError>;

    /// Rotate a credential's secret value.
    async fn rotate(&self, credential_id: &str) -> Result<(), VaultError>;

    /// Revoke a credential.
    async fn revoke(&self, credential_id: &str) -> Result<(), VaultError>;

    /// Retrieve audit events for a credential.
    async fn audit_log(
        &self,
        credential_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<AuditEvent>, VaultError>;
}
