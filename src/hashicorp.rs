use chrono::Utc;
use reqwest::Client;
use uuid::Uuid;

use crate::backend::VaultBackend;
use crate::error::VaultError;
use crate::types::*;

/// HashiCorp Vault KV v2 backend.
pub struct HashicorpBackend {
    client: Client,
    addr: String,
    token: String,
    mount: String,
}

impl HashicorpBackend {
    pub fn new(addr: String, token: String, mount: Option<String>) -> Self {
        Self {
            client: Client::new(),
            addr,
            token,
            mount: mount.unwrap_or_else(|| "secret".into()),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}/v1/{}/data/{}", self.addr, self.mount, path)
    }

    fn metadata_url(&self, path: &str) -> String {
        format!("{}/v1/{}/metadata/{}", self.addr, self.mount, path)
    }
}

#[async_trait::async_trait]
impl VaultBackend for HashicorpBackend {
    fn backend_type(&self) -> BackendType {
        BackendType::Hashicorp
    }

    async fn health_check(&self) -> Result<(), VaultError> {
        let resp = self
            .client
            .get(format!("{}/v1/sys/health", self.addr))
            .send()
            .await
            .map_err(|e| VaultError::Unavailable(e.to_string()))?;
        if resp.status().is_success() || resp.status().as_u16() == 429 {
            Ok(())
        } else {
            Err(VaultError::Unavailable(format!("status: {}", resp.status())))
        }
    }

    async fn list_credentials(&self) -> Result<Vec<Credential>, VaultError> {
        let resp = self
            .client
            .request(
                reqwest::Method::from_bytes(b"LIST").unwrap(),
                self.metadata_url(""),
            )
            .header("X-Vault-Token", &self.token)
            .send()
            .await
            .map_err(|e| VaultError::Unavailable(e.to_string()))?;

        if resp.status() == 404 {
            return Ok(vec![]);
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| VaultError::Internal(e.to_string()))?;

        let keys = body["data"]["keys"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|v| v.as_str())
            .map(|key| Credential {
                id: format!("vault://{}", key),
                display_name: key.to_string(),
                owner: "hashicorp".into(),
                scope: vec![],
                backend: BackendType::Hashicorp,
                risk_level: adk_mcp_sdk::risk::RiskLevel::Medium,
                rotation_policy: None,
                expires_at: None,
                last_rotated: None,
                last_accessed: None,
                status: CredentialStatus::Active,
                tags: vec![],
            })
            .collect();

        Ok(keys)
    }

    async fn get_credential(&self, id: &str) -> Result<Credential, VaultError> {
        let path = id.strip_prefix("vault://").unwrap_or(id);
        let resp = self
            .client
            .get(self.metadata_url(path))
            .header("X-Vault-Token", &self.token)
            .send()
            .await
            .map_err(|e| VaultError::Unavailable(e.to_string()))?;

        if resp.status() == 404 {
            return Err(VaultError::NotFound(id.to_string()));
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| VaultError::Internal(e.to_string()))?;

        let created = body["data"]["created_time"].as_str();
        let updated = body["data"]["updated_time"].as_str();

        Ok(Credential {
            id: format!("vault://{}", path),
            display_name: path.to_string(),
            owner: "hashicorp".into(),
            scope: vec![],
            backend: BackendType::Hashicorp,
            risk_level: adk_mcp_sdk::risk::RiskLevel::Medium,
            rotation_policy: None,
            expires_at: None,
            last_rotated: updated.and_then(|s| s.parse().ok()),
            last_accessed: created.and_then(|s| s.parse().ok()),
            status: CredentialStatus::Active,
            tags: vec![],
        })
    }

    async fn issue_runtime_handle(
        &self,
        credential_id: &str,
        scope: &[String],
        ttl_seconds: u64,
    ) -> Result<RuntimeSecretHandle, VaultError> {
        // Verify credential exists (we don't return the secret value)
        let _ = self.get_credential(credential_id).await?;

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
        let _ = self.get_credential(credential_id).await?;

        Ok(WorkloadToken {
            token_id: Uuid::new_v4().to_string(),
            credential_id: credential_id.to_string(),
            token_type: "vault-token".into(),
            expires_at: Utc::now() + chrono::Duration::seconds(ttl_seconds as i64),
            audience: audience.to_string(),
        })
    }

    async fn rotate(&self, credential_id: &str) -> Result<(), VaultError> {
        let path = credential_id.strip_prefix("vault://").unwrap_or(credential_id);
        // Write a new version with a generated value
        let new_value = Uuid::new_v4().to_string();
        let payload = serde_json::json!({ "data": { "value": new_value } });

        let resp = self
            .client
            .post(self.url(path))
            .header("X-Vault-Token", &self.token)
            .json(&payload)
            .send()
            .await
            .map_err(|e| VaultError::RotationFailed(e.to_string()))?;

        if resp.status().is_success() {
            Ok(())
        } else {
            Err(VaultError::RotationFailed(format!("status: {}", resp.status())))
        }
    }

    async fn revoke(&self, credential_id: &str) -> Result<(), VaultError> {
        let path = credential_id.strip_prefix("vault://").unwrap_or(credential_id);
        let resp = self
            .client
            .delete(self.metadata_url(path))
            .header("X-Vault-Token", &self.token)
            .send()
            .await
            .map_err(|e| VaultError::Internal(e.to_string()))?;

        if resp.status().is_success() || resp.status() == 404 {
            Ok(())
        } else {
            Err(VaultError::Internal(format!("status: {}", resp.status())))
        }
    }

    async fn audit_log(
        &self,
        _credential_id: Option<&str>,
        _limit: usize,
    ) -> Result<Vec<AuditEvent>, VaultError> {
        // HashiCorp Vault audit logs are file/syslog-based, not queryable via API.
        // Return empty — real impl would read from audit device or external log store.
        Ok(vec![])
    }
}
