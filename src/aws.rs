use aws_sdk_secretsmanager::Client as SmClient;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::backend::VaultBackend;
use crate::error::VaultError;
use crate::types::*;

/// AWS Secrets Manager backend.
pub struct AwsBackend {
    client: SmClient,
}

impl AwsBackend {
    pub async fn new(region: Option<String>) -> Self {
        let mut config_loader = aws_config::from_env();
        if let Some(r) = region {
            config_loader = config_loader.region(aws_config::Region::new(r));
        }
        let config = config_loader.load().await;
        Self {
            client: SmClient::new(&config),
        }
    }

    pub fn from_client(client: SmClient) -> Self {
        Self { client }
    }
}

#[async_trait::async_trait]
impl VaultBackend for AwsBackend {
    fn backend_type(&self) -> BackendType {
        BackendType::Aws
    }

    async fn health_check(&self) -> Result<(), VaultError> {
        self.client
            .list_secrets()
            .max_results(1)
            .send()
            .await
            .map_err(|e| VaultError::Unavailable(e.to_string()))?;
        Ok(())
    }

    async fn list_credentials(&self) -> Result<Vec<Credential>, VaultError> {
        let resp = self
            .client
            .list_secrets()
            .send()
            .await
            .map_err(|e| VaultError::Unavailable(e.to_string()))?;

        let creds = resp
            .secret_list()
            .iter()
            .map(|s| {
                let name = s.name().unwrap_or("unknown");
                Credential {
                    id: format!("vault://{}", name),
                    display_name: name.to_string(),
                    owner: "aws".into(),
                    scope: vec![],
                    backend: BackendType::Aws,
                    risk_level: adk_mcp_sdk::risk::RiskLevel::Medium,
                    rotation_policy: s.rotation_enabled().unwrap_or(false).then_some(RotationPolicy {
                        interval_days: s
                            .rotation_rules()
                            .and_then(|r| r.automatically_after_days)
                            .map(|d| d as u32)
                            .unwrap_or(90),
                        auto_rotate: true,
                        notify_before_days: Some(7),
                    }),
                    expires_at: None,
                    last_rotated: s.last_rotated_date().map(|d| {
                        DateTime::from_timestamp(d.secs(), d.subsec_nanos())
                            .unwrap_or_default()
                    }),
                    last_accessed: s.last_accessed_date().map(|d| {
                        DateTime::from_timestamp(d.secs(), d.subsec_nanos())
                            .unwrap_or_default()
                    }),
                    status: if s.deleted_date().is_some() {
                        CredentialStatus::Revoked
                    } else {
                        CredentialStatus::Active
                    },
                    tags: s
                        .tags()
                        .iter()
                        .filter_map(|t| {
                            Some(format!("{}={}", t.key()?, t.value()?))
                        })
                        .collect(),
                }
            })
            .collect();

        Ok(creds)
    }

    async fn get_credential(&self, id: &str) -> Result<Credential, VaultError> {
        let name = id.strip_prefix("vault://").unwrap_or(id);
        let resp = self
            .client
            .describe_secret()
            .secret_id(name)
            .send()
            .await
            .map_err(|e| VaultError::NotFound(e.to_string()))?;

        Ok(Credential {
            id: format!("vault://{}", name),
            display_name: resp.name().unwrap_or(name).to_string(),
            owner: "aws".into(),
            scope: vec![],
            backend: BackendType::Aws,
            risk_level: adk_mcp_sdk::risk::RiskLevel::Medium,
            rotation_policy: resp.rotation_enabled().unwrap_or(false).then_some(RotationPolicy {
                interval_days: resp
                    .rotation_rules()
                    .and_then(|r| r.automatically_after_days)
                    .map(|d| d as u32)
                    .unwrap_or(90),
                auto_rotate: true,
                notify_before_days: Some(7),
            }),
            expires_at: None,
            last_rotated: resp.last_rotated_date().map(|d| {
                DateTime::from_timestamp(d.secs(), d.subsec_nanos()).unwrap_or_default()
            }),
            last_accessed: resp.last_accessed_date().map(|d| {
                DateTime::from_timestamp(d.secs(), d.subsec_nanos()).unwrap_or_default()
            }),
            status: if resp.deleted_date().is_some() {
                CredentialStatus::Revoked
            } else {
                CredentialStatus::Active
            },
            tags: resp
                .tags()
                .iter()
                .filter_map(|t| Some(format!("{}={}", t.key()?, t.value()?)))
                .collect(),
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
            token_type: "aws-session".into(),
            expires_at: Utc::now() + chrono::Duration::seconds(ttl_seconds as i64),
            audience: audience.to_string(),
        })
    }

    async fn rotate(&self, credential_id: &str) -> Result<(), VaultError> {
        let name = credential_id.strip_prefix("vault://").unwrap_or(credential_id);
        self.client
            .rotate_secret()
            .secret_id(name)
            .send()
            .await
            .map_err(|e| VaultError::RotationFailed(e.to_string()))?;
        Ok(())
    }

    async fn revoke(&self, credential_id: &str) -> Result<(), VaultError> {
        let name = credential_id.strip_prefix("vault://").unwrap_or(credential_id);
        self.client
            .delete_secret()
            .secret_id(name)
            .send()
            .await
            .map_err(|e| VaultError::Internal(e.to_string()))?;
        Ok(())
    }

    async fn audit_log(
        &self,
        _credential_id: Option<&str>,
        _limit: usize,
    ) -> Result<Vec<AuditEvent>, VaultError> {
        // AWS audit is via CloudTrail — not directly queryable here.
        Ok(vec![])
    }
}
