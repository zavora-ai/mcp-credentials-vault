use std::sync::Arc;

use chrono::Utc;
use reqwest::Client;
use uuid::Uuid;

use crate::backend::VaultBackend;
use crate::error::VaultError;
use crate::types::*;

/// GCP Secret Manager backend.
pub struct GcpBackend {
    client: Client,
    project_id: String,
    token_provider: Arc<dyn gcp_auth::TokenProvider>,
}

impl GcpBackend {
    pub async fn new(project_id: String) -> Result<Self, VaultError> {
        let provider = gcp_auth::provider().await
            .map_err(|e| VaultError::AuthFailed(e.to_string()))?;
        Ok(Self {
            client: Client::new(),
            project_id,
            token_provider: provider,
        })
    }

    async fn token(&self) -> Result<String, VaultError> {
        let scopes = &["https://www.googleapis.com/auth/cloud-platform"];
        let token = self
            .token_provider
            .token(scopes)
            .await
            .map_err(|e| VaultError::AuthFailed(e.to_string()))?;
        Ok(token.as_str().to_string())
    }

    fn base_url(&self) -> String {
        format!(
            "https://secretmanager.googleapis.com/v1/projects/{}",
            self.project_id
        )
    }
}

#[async_trait::async_trait]
impl VaultBackend for GcpBackend {
    fn backend_type(&self) -> BackendType {
        BackendType::Gcp
    }

    async fn health_check(&self) -> Result<(), VaultError> {
        let token = self.token().await?;
        let resp = self
            .client
            .get(format!("{}/secrets?pageSize=1", self.base_url()))
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| VaultError::Unavailable(e.to_string()))?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(VaultError::Unavailable(format!("status: {}", resp.status())))
        }
    }

    async fn list_credentials(&self) -> Result<Vec<Credential>, VaultError> {
        let token = self.token().await?;
        let resp = self
            .client
            .get(format!("{}/secrets", self.base_url()))
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| VaultError::Unavailable(e.to_string()))?;

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| VaultError::Internal(e.to_string()))?;

        let creds = body["secrets"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .map(|s| {
                let name = s["name"].as_str().unwrap_or("");
                let short_name = name.rsplit('/').next().unwrap_or(name);
                Credential {
                    id: format!("vault://{}", short_name),
                    display_name: short_name.to_string(),
                    owner: "gcp".into(),
                    scope: vec![],
                    backend: BackendType::Gcp,
                    risk_level: adk_mcp_sdk::risk::RiskLevel::Medium,
                    rotation_policy: None,
                    expires_at: None,
                    last_rotated: None,
                    last_accessed: None,
                    status: CredentialStatus::Active,
                    tags: s["labels"]
                        .as_object()
                        .map(|m| m.iter().map(|(k, v)| format!("{}={}", k, v)).collect())
                        .unwrap_or_default(),
                }
            })
            .collect();

        Ok(creds)
    }

    async fn get_credential(&self, id: &str) -> Result<Credential, VaultError> {
        let name = id.strip_prefix("vault://").unwrap_or(id);
        let token = self.token().await?;
        let resp = self
            .client
            .get(format!("{}/secrets/{}", self.base_url(), name))
            .bearer_auth(&token)
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

        Ok(Credential {
            id: format!("vault://{}", name),
            display_name: name.to_string(),
            owner: "gcp".into(),
            scope: vec![],
            backend: BackendType::Gcp,
            risk_level: adk_mcp_sdk::risk::RiskLevel::Medium,
            rotation_policy: None,
            expires_at: None,
            last_rotated: None,
            last_accessed: None,
            status: CredentialStatus::Active,
            tags: body["labels"]
                .as_object()
                .map(|m| m.iter().map(|(k, v)| format!("{}={}", k, v)).collect())
                .unwrap_or_default(),
        })
    }

    async fn issue_runtime_handle(
        &self,
        credential_id: &str,
        scope: &[String],
        ttl_seconds: u64,
    ) -> Result<RuntimeSecretHandle, VaultError> {
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
            token_type: "gcp-identity".into(),
            expires_at: Utc::now() + chrono::Duration::seconds(ttl_seconds as i64),
            audience: audience.to_string(),
        })
    }

    async fn rotate(&self, credential_id: &str) -> Result<(), VaultError> {
        let name = credential_id.strip_prefix("vault://").unwrap_or(credential_id);
        let token = self.token().await?;
        let new_value = Uuid::new_v4().to_string();
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            new_value.as_bytes(),
        );
        let payload = serde_json::json!({
            "payload": { "data": encoded }
        });
        let resp = self
            .client
            .post(format!("{}/secrets/{}:addVersion", self.base_url(), name))
            .bearer_auth(&token)
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
        let name = credential_id.strip_prefix("vault://").unwrap_or(credential_id);
        let token = self.token().await?;
        let resp = self
            .client
            .delete(format!("{}/secrets/{}", self.base_url(), name))
            .bearer_auth(&token)
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
        Ok(vec![])
    }
}
