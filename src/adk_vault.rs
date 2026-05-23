use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::backend::VaultBackend;
use crate::error::VaultError;
use crate::types::*;

/// Internal ADK Vault — in-memory store for platform-managed credentials.
/// Optionally persists to a JSON file for durability across restarts.
pub struct AdkVaultBackend {
    credentials: Arc<RwLock<HashMap<String, Credential>>>,
    audit_events: Arc<RwLock<Vec<AuditEvent>>>,
    persist_path: Option<std::path::PathBuf>,
}

impl AdkVaultBackend {
    pub fn new(persist_path: Option<std::path::PathBuf>) -> Self {
        let credentials = if let Some(ref path) = persist_path {
            Self::load_from_file(path).unwrap_or_default()
        } else {
            HashMap::new()
        };

        Self {
            credentials: Arc::new(RwLock::new(credentials)),
            audit_events: Arc::new(RwLock::new(Vec::new())),
            persist_path,
        }
    }

    fn load_from_file(path: &std::path::Path) -> Option<HashMap<String, Credential>> {
        let data = std::fs::read_to_string(path).ok()?;
        serde_json::from_str(&data).ok()
    }

    async fn persist(&self) {
        if let Some(ref path) = self.persist_path {
            let creds = self.credentials.read().await;
            if let Ok(data) = serde_json::to_string_pretty(&*creds) {
                let _ = std::fs::write(path, data);
            }
        }
    }

    async fn record_audit(&self, credential_id: &str, action: AuditAction, outcome: AuditOutcome) {
        let event = AuditEvent {
            event_id: Uuid::new_v4().to_string(),
            credential_id: credential_id.to_string(),
            action,
            actor: "system".into(),
            timestamp: Utc::now(),
            outcome,
            reason: None,
        };
        self.audit_events.write().await.push(event);
    }

    /// Insert a credential (for testing or platform provisioning).
    pub async fn insert(&self, credential: Credential) {
        let id = credential.id.clone();
        self.credentials.write().await.insert(id, credential);
        self.persist().await;
    }
}

#[async_trait::async_trait]
impl VaultBackend for AdkVaultBackend {
    fn backend_type(&self) -> BackendType {
        BackendType::AdkVault
    }

    async fn health_check(&self) -> Result<(), VaultError> {
        Ok(()) // In-memory is always healthy
    }

    async fn list_credentials(&self) -> Result<Vec<Credential>, VaultError> {
        let creds = self.credentials.read().await;
        Ok(creds.values().cloned().collect())
    }

    async fn get_credential(&self, id: &str) -> Result<Credential, VaultError> {
        let creds = self.credentials.read().await;
        creds
            .get(id)
            .cloned()
            .ok_or_else(|| VaultError::NotFound(id.to_string()))
    }

    async fn issue_runtime_handle(
        &self,
        credential_id: &str,
        scope: &[String],
        ttl_seconds: u64,
    ) -> Result<RuntimeSecretHandle, VaultError> {
        let creds = self.credentials.read().await;
        if !creds.contains_key(credential_id) {
            self.record_audit(credential_id, AuditAction::Denied, AuditOutcome::Denied)
                .await;
            return Err(VaultError::NotFound(credential_id.to_string()));
        }
        drop(creds);

        self.record_audit(credential_id, AuditAction::Access, AuditOutcome::Success)
            .await;

        Ok(RuntimeSecretHandle {
            handle_id: Uuid::new_v4().to_string(),
            credential_id: credential_id.to_string(),
            expires_at: Utc::now() + chrono::Duration::seconds(ttl_seconds as i64),
            scope: scope.to_vec(),
        })
    }

    async fn mint_workload_token(
        &self,
        credential_id: &str,
        audience: &str,
        ttl_seconds: u64,
    ) -> Result<WorkloadToken, VaultError> {
        let creds = self.credentials.read().await;
        if !creds.contains_key(credential_id) {
            return Err(VaultError::NotFound(credential_id.to_string()));
        }
        drop(creds);

        self.record_audit(credential_id, AuditAction::TokenMinted, AuditOutcome::Success)
            .await;

        Ok(WorkloadToken {
            token_id: Uuid::new_v4().to_string(),
            credential_id: credential_id.to_string(),
            token_type: "adk-internal".into(),
            expires_at: Utc::now() + chrono::Duration::seconds(ttl_seconds as i64),
            audience: audience.to_string(),
        })
    }

    async fn rotate(&self, credential_id: &str) -> Result<(), VaultError> {
        let mut creds = self.credentials.write().await;
        let cred = creds
            .get_mut(credential_id)
            .ok_or_else(|| VaultError::NotFound(credential_id.to_string()))?;
        cred.last_rotated = Some(Utc::now());
        cred.status = CredentialStatus::Active;
        drop(creds);

        self.record_audit(credential_id, AuditAction::Rotated, AuditOutcome::Success)
            .await;
        self.persist().await;
        Ok(())
    }

    async fn revoke(&self, credential_id: &str) -> Result<(), VaultError> {
        let mut creds = self.credentials.write().await;
        let cred = creds
            .get_mut(credential_id)
            .ok_or_else(|| VaultError::NotFound(credential_id.to_string()))?;
        cred.status = CredentialStatus::Revoked;
        drop(creds);

        self.record_audit(credential_id, AuditAction::Revoked, AuditOutcome::Success)
            .await;
        self.persist().await;
        Ok(())
    }

    async fn audit_log(
        &self,
        credential_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<AuditEvent>, VaultError> {
        let events = self.audit_events.read().await;
        let filtered: Vec<_> = events
            .iter()
            .rev()
            .filter(|e| credential_id.is_none() || credential_id == Some(e.credential_id.as_str()))
            .take(limit)
            .cloned()
            .collect();
        Ok(filtered)
    }
}
