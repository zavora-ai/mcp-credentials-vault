use chrono::{DateTime, Utc};
use reqwest::Client;

use crate::backend::VaultBackend;
use crate::error::VaultError;
use crate::types::*;

/// Backend that delegates to the ADK-Rust Enterprise Platform API.
pub struct AdkPlatformBackend {
    client: Client,
    base_url: String,
    api_key: String,
    workspace_id: String,
}

impl AdkPlatformBackend {
    pub fn new(base_url: String, api_key: String, workspace_id: String) -> Self {
        Self {
            client: Client::new(),
            base_url: base_url.trim_end_matches('/').to_string(),
            api_key,
            workspace_id,
        }
    }

    pub fn from_env() -> Option<Self> {
        Some(Self::new(
            std::env::var("ADK_PLATFORM_URL").ok()?,
            std::env::var("ADK_PLATFORM_API_KEY").ok()?,
            std::env::var("ADK_WORKSPACE_ID").ok()?,
        ))
    }

    fn url(&self, path: &str) -> String {
        format!("{}/api/v1{}", self.base_url, path)
    }

    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        self.client
            .request(method, self.url(path))
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("X-Workspace-Id", &self.workspace_id)
    }

    fn parse_credential(v: &serde_json::Value) -> Credential {
        Credential {
            id: format!("vault://{}", v["id"].as_str().unwrap_or("")),
            display_name: v["display_name"]
                .as_str()
                .or(v["name"].as_str())
                .unwrap_or("")
                .to_string(),
            owner: v["owner"].as_str().unwrap_or("platform").to_string(),
            scope: v["scope"]
                .as_array()
                .map(|a| a.iter().filter_map(|s| s.as_str().map(String::from)).collect())
                .unwrap_or_default(),
            backend: BackendType::AdkVault,
            risk_level: match v["risk_level"].as_str().unwrap_or("medium") {
                "low" => adk_mcp_sdk::risk::RiskLevel::Low,
                "high" => adk_mcp_sdk::risk::RiskLevel::High,
                "critical" => adk_mcp_sdk::risk::RiskLevel::Critical,
                _ => adk_mcp_sdk::risk::RiskLevel::Medium,
            },
            rotation_policy: v["rotation_policy"].as_object().map(|r| RotationPolicy {
                interval_days: r.get("interval_days").and_then(|v| v.as_u64()).unwrap_or(90) as u32,
                auto_rotate: r.get("auto_rotate").and_then(|v| v.as_bool()).unwrap_or(false),
                notify_before_days: r.get("notify_before_days").and_then(|v| v.as_u64()).map(|d| d as u32),
            }),
            expires_at: v["expires_at"].as_str().and_then(|s| s.parse::<DateTime<Utc>>().ok()),
            last_rotated: v["last_rotated_at"].as_str().and_then(|s| s.parse::<DateTime<Utc>>().ok()),
            last_accessed: v["last_accessed_at"].as_str().and_then(|s| s.parse::<DateTime<Utc>>().ok()),
            status: match v["status"].as_str().unwrap_or("active") {
                "expired" => CredentialStatus::Expired,
                "revoked" => CredentialStatus::Revoked,
                "rotating" => CredentialStatus::Rotating,
                _ => CredentialStatus::Active,
            },
            tags: v["tags"]
                .as_array()
                .map(|a| a.iter().filter_map(|s| s.as_str().map(String::from)).collect())
                .unwrap_or_default(),
        }
    }
}

#[async_trait::async_trait]
impl VaultBackend for AdkPlatformBackend {
    fn backend_type(&self) -> BackendType {
        BackendType::AdkVault
    }

    async fn health_check(&self) -> Result<(), VaultError> {
        let resp = self
            .request(reqwest::Method::GET, "/credentials")
            .query(&[("limit", "1")])
            .send()
            .await
            .map_err(|e| VaultError::Unavailable(e.to_string()))?;
        if resp.status().is_success() {
            Ok(())
        } else if resp.status() == 401 || resp.status() == 403 {
            Err(VaultError::AuthFailed("invalid API key or workspace".into()))
        } else {
            Err(VaultError::Unavailable(format!("status: {}", resp.status())))
        }
    }

    async fn list_credentials(&self) -> Result<Vec<Credential>, VaultError> {
        let resp = self
            .request(reqwest::Method::GET, "/credentials")
            .send()
            .await
            .map_err(|e| VaultError::Unavailable(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(VaultError::Unavailable(format!("status: {}", resp.status())));
        }

        let body: serde_json::Value = resp.json().await
            .map_err(|e| VaultError::Internal(e.to_string()))?;

        let items = body["data"].as_array()
            .or(body.as_array())
            .cloned()
            .unwrap_or_default();

        Ok(items.iter().map(Self::parse_credential).collect())
    }

    async fn get_credential(&self, id: &str) -> Result<Credential, VaultError> {
        let cred_id = id.strip_prefix("vault://").unwrap_or(id);
        let resp = self
            .request(reqwest::Method::GET, &format!("/credentials/{}", cred_id))
            .send()
            .await
            .map_err(|e| VaultError::Unavailable(e.to_string()))?;

        if resp.status() == 404 {
            return Err(VaultError::NotFound(id.to_string()));
        }
        if !resp.status().is_success() {
            return Err(VaultError::Internal(format!("status: {}", resp.status())));
        }

        let body: serde_json::Value = resp.json().await
            .map_err(|e| VaultError::Internal(e.to_string()))?;

        let data = if body.get("data").is_some() { &body["data"] } else { &body };
        Ok(Self::parse_credential(data))
    }

    async fn issue_runtime_handle(
        &self,
        credential_id: &str,
        scope: &[String],
        ttl_seconds: u64,
    ) -> Result<RuntimeSecretHandle, VaultError> {
        let cred_id = credential_id.strip_prefix("vault://").unwrap_or(credential_id);
        let payload = serde_json::json!({
            "scope": scope,
            "ttl_seconds": ttl_seconds,
        });

        let resp = self
            .request(reqwest::Method::POST, &format!("/credentials/{}/runtime-handle", cred_id))
            .json(&payload)
            .send()
            .await
            .map_err(|e| VaultError::Unavailable(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(VaultError::Internal(format!("status: {} body: {}", status, body)));
        }

        let body: serde_json::Value = resp.json().await
            .map_err(|e| VaultError::Internal(e.to_string()))?;

        Ok(RuntimeSecretHandle {
            handle_id: body["handle_id"].as_str().unwrap_or("").to_string(),
            credential_id: credential_id.to_string(),
            expires_at: body["expires_at"]
                .as_str()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(|| Utc::now() + chrono::Duration::seconds(ttl_seconds as i64)),
            scope: scope.to_vec(),
        })
    }

    async fn mint_workload_token(
        &self,
        credential_id: &str,
        audience: &str,
        ttl_seconds: u64,
    ) -> Result<WorkloadToken, VaultError> {
        let cred_id = credential_id.strip_prefix("vault://").unwrap_or(credential_id);
        let payload = serde_json::json!({
            "audience": audience,
            "ttl_seconds": ttl_seconds,
        });

        let resp = self
            .request(reqwest::Method::POST, &format!("/credentials/{}/workload-token", cred_id))
            .json(&payload)
            .send()
            .await
            .map_err(|e| VaultError::Unavailable(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(VaultError::TokenMintFailed(format!("status: {} body: {}", status, body)));
        }

        let body: serde_json::Value = resp.json().await
            .map_err(|e| VaultError::Internal(e.to_string()))?;

        Ok(WorkloadToken {
            token_id: body["token_id"].as_str().unwrap_or("").to_string(),
            credential_id: credential_id.to_string(),
            token_type: body["token_type"].as_str().unwrap_or("platform").to_string(),
            expires_at: body["expires_at"]
                .as_str()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(|| Utc::now() + chrono::Duration::seconds(ttl_seconds as i64)),
            audience: audience.to_string(),
        })
    }

    async fn rotate(&self, credential_id: &str) -> Result<(), VaultError> {
        let cred_id = credential_id.strip_prefix("vault://").unwrap_or(credential_id);
        let resp = self
            .request(reqwest::Method::POST, &format!("/credentials/{}/rotate", cred_id))
            .send()
            .await
            .map_err(|e| VaultError::RotationFailed(e.to_string()))?;

        if resp.status().is_success() {
            Ok(())
        } else {
            let body = resp.text().await.unwrap_or_default();
            Err(VaultError::RotationFailed(body))
        }
    }

    async fn revoke(&self, credential_id: &str) -> Result<(), VaultError> {
        let cred_id = credential_id.strip_prefix("vault://").unwrap_or(credential_id);
        let resp = self
            .request(reqwest::Method::DELETE, &format!("/credentials/{}", cred_id))
            .send()
            .await
            .map_err(|e| VaultError::Internal(e.to_string()))?;

        if resp.status().is_success() || resp.status() == 404 {
            Ok(())
        } else {
            let body = resp.text().await.unwrap_or_default();
            Err(VaultError::Internal(body))
        }
    }

    async fn audit_log(
        &self,
        credential_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<AuditEvent>, VaultError> {
        let mut query = vec![
            ("resource_type".to_string(), "credentials".to_string()),
            ("limit".to_string(), limit.to_string()),
        ];
        if let Some(id) = credential_id {
            let cred_id = id.strip_prefix("vault://").unwrap_or(id);
            query.push(("resource_id".to_string(), cred_id.to_string()));
        }

        let resp = self
            .request(reqwest::Method::GET, "/admin/audit")
            .query(&query)
            .send()
            .await
            .map_err(|e| VaultError::Unavailable(e.to_string()))?;

        if !resp.status().is_success() {
            return Ok(vec![]);
        }

        let body: serde_json::Value = resp.json().await
            .map_err(|e| VaultError::Internal(e.to_string()))?;

        let items = body["data"].as_array()
            .or(body.as_array())
            .cloned()
            .unwrap_or_default();

        let events = items.iter().map(|e| AuditEvent {
            event_id: e["id"].as_str().unwrap_or("").to_string(),
            credential_id: format!("vault://{}", e["resource_id"].as_str().unwrap_or("")),
            action: match e["action"].as_str().unwrap_or("") {
                "access" | "read" => AuditAction::Access,
                "denied" => AuditAction::Denied,
                "rotated" | "rotate" => AuditAction::Rotated,
                "revoked" | "revoke" | "delete" => AuditAction::Revoked,
                "token_minted" => AuditAction::TokenMinted,
                _ => AuditAction::ScopeValidated,
            },
            actor: e["actor"].as_str().unwrap_or("system").to_string(),
            timestamp: e["created_at"]
                .as_str()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(Utc::now),
            outcome: match e["outcome"].as_str().unwrap_or("success") {
                "denied" => AuditOutcome::Denied,
                "error" => AuditOutcome::Error,
                _ => AuditOutcome::Success,
            },
            reason: e["reason"].as_str().map(String::from),
        }).collect();

        Ok(events)
    }
}
