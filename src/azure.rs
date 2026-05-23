use chrono::Utc;
use reqwest::Client;
use uuid::Uuid;

use crate::backend::VaultBackend;
use crate::error::VaultError;
use crate::types::*;

/// Azure Key Vault backend.
pub struct AzureBackend {
    client: Client,
    vault_url: String,
    access_token: String,
}

impl AzureBackend {
    pub fn new(vault_url: String, access_token: String) -> Self {
        Self {
            client: Client::new(),
            vault_url: vault_url.trim_end_matches('/').to_string(),
            access_token,
        }
    }

    fn secrets_url(&self) -> String {
        format!("{}/secrets?api-version=7.4", self.vault_url)
    }

    fn secret_url(&self, name: &str) -> String {
        format!("{}/secrets/{}?api-version=7.4", self.vault_url, name)
    }
}

#[async_trait::async_trait]
impl VaultBackend for AzureBackend {
    fn backend_type(&self) -> BackendType {
        BackendType::Azure
    }

    async fn health_check(&self) -> Result<(), VaultError> {
        let resp = self
            .client
            .get(&self.secrets_url())
            .bearer_auth(&self.access_token)
            .query(&[("maxresults", "1")])
            .send()
            .await
            .map_err(|e| VaultError::Unavailable(e.to_string()))?;
        if resp.status().is_success() {
            Ok(())
        } else if resp.status() == 401 {
            Err(VaultError::AuthFailed("token expired or invalid".into()))
        } else {
            Err(VaultError::Unavailable(format!("status: {}", resp.status())))
        }
    }

    async fn list_credentials(&self) -> Result<Vec<Credential>, VaultError> {
        let resp = self
            .client
            .get(&self.secrets_url())
            .bearer_auth(&self.access_token)
            .send()
            .await
            .map_err(|e| VaultError::Unavailable(e.to_string()))?;

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| VaultError::Internal(e.to_string()))?;

        let creds = body["value"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .map(|s| {
                let id_url = s["id"].as_str().unwrap_or("");
                let name = id_url.rsplit('/').next().unwrap_or(id_url);
                let enabled = s["attributes"]["enabled"].as_bool().unwrap_or(true);
                Credential {
                    id: format!("vault://{}", name),
                    display_name: name.to_string(),
                    owner: "azure".into(),
                    scope: vec![],
                    backend: BackendType::Azure,
                    risk_level: adk_mcp_sdk::risk::RiskLevel::Medium,
                    rotation_policy: None,
                    expires_at: s["attributes"]["exp"]
                        .as_i64()
                        .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0)),
                    last_rotated: s["attributes"]["updated"]
                        .as_i64()
                        .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0)),
                    last_accessed: None,
                    status: if !enabled {
                        CredentialStatus::Revoked
                    } else {
                        CredentialStatus::Active
                    },
                    tags: s["tags"]
                        .as_object()
                        .map(|m| {
                            m.iter()
                                .map(|(k, v)| format!("{}={}", k, v.as_str().unwrap_or("")))
                                .collect()
                        })
                        .unwrap_or_default(),
                }
            })
            .collect();

        Ok(creds)
    }

    async fn get_credential(&self, id: &str) -> Result<Credential, VaultError> {
        let name = id.strip_prefix("vault://").unwrap_or(id);
        let resp = self
            .client
            .get(&self.secret_url(name))
            .bearer_auth(&self.access_token)
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

        let enabled = body["attributes"]["enabled"].as_bool().unwrap_or(true);
        Ok(Credential {
            id: format!("vault://{}", name),
            display_name: name.to_string(),
            owner: "azure".into(),
            scope: vec![],
            backend: BackendType::Azure,
            risk_level: adk_mcp_sdk::risk::RiskLevel::Medium,
            rotation_policy: None,
            expires_at: body["attributes"]["exp"]
                .as_i64()
                .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0)),
            last_rotated: body["attributes"]["updated"]
                .as_i64()
                .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0)),
            last_accessed: None,
            status: if !enabled {
                CredentialStatus::Revoked
            } else {
                CredentialStatus::Active
            },
            tags: vec![],
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
            token_type: "azure-ad".into(),
            expires_at: Utc::now() + chrono::Duration::seconds(ttl_seconds as i64),
            audience: audience.to_string(),
        })
    }

    async fn rotate(&self, credential_id: &str) -> Result<(), VaultError> {
        let name = credential_id.strip_prefix("vault://").unwrap_or(credential_id);
        let new_value = Uuid::new_v4().to_string();
        let payload = serde_json::json!({ "value": new_value });

        let resp = self
            .client
            .put(&self.secret_url(name))
            .bearer_auth(&self.access_token)
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
        // Azure: disable the secret rather than delete
        let payload = serde_json::json!({ "attributes": { "enabled": false } });
        let resp = self
            .client
            .patch(&self.secret_url(name))
            .bearer_auth(&self.access_token)
            .json(&payload)
            .send()
            .await
            .map_err(|e| VaultError::Internal(e.to_string()))?;

        if resp.status().is_success() {
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
        // Azure audit is via Azure Monitor / Activity Log.
        Ok(vec![])
    }
}
