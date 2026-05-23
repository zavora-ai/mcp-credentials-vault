# Backend Configuration

## Overview

The Credentials Vault MCP server supports 5 pluggable backends. Enable them via Cargo feature flags:

```toml
# Single backend
mcp-credentials-vault = { version = "1.0", features = ["aws"] }

# Multiple backends
mcp-credentials-vault = { version = "1.0", features = ["aws", "gcp", "adk-vault"] }

# All backends
mcp-credentials-vault = { version = "1.0", features = ["all-backends"] }
```

---

## ADK Vault (Internal)

**Feature:** `adk-vault` (enabled by default)

In-memory credential store with optional file persistence. Ideal for:
- Platform-managed credentials
- Development and testing
- Credentials that don't need an external vault

### Configuration

| Env Variable | Description |
|-------------|-------------|
| `ADK_VAULT_PATH` | Path to JSON persistence file (optional) |

### Capabilities

- ✅ Full CRUD lifecycle
- ✅ Audit logging (in-memory)
- ✅ Scope enforcement
- ✅ Rotation (updates timestamp)
- ✅ File persistence across restarts

### Usage

```rust
use mcp_credentials_vault::adk_vault::AdkVaultBackend;

// In-memory only
let backend = AdkVaultBackend::new(None);

// With file persistence
let backend = AdkVaultBackend::new(Some("./vault.json".into()));
```

---

## AWS Secrets Manager

**Feature:** `aws`

Uses the official AWS SDK. Authenticates via standard AWS credential chain (env vars, IAM role, SSO, credential file).

### Configuration

| Env Variable | Description |
|-------------|-------------|
| `AWS_REGION` or `AWS_DEFAULT_REGION` | AWS region |
| `AWS_ACCESS_KEY_ID` | Access key (or use IAM role) |
| `AWS_SECRET_ACCESS_KEY` | Secret key (or use IAM role) |
| `AWS_SESSION_TOKEN` | Session token (for temporary creds) |

### Capabilities

- ✅ List all secrets
- ✅ Describe secret metadata
- ✅ Rotation (triggers AWS rotation Lambda)
- ✅ Revocation (deletes secret)
- ⚠️ Audit via CloudTrail (not queryable from this server)

### Usage

```rust
use mcp_credentials_vault::aws::AwsBackend;

let backend = AwsBackend::new(Some("us-east-1".into())).await;
```

---

## GCP Secret Manager

**Feature:** `gcp`

Uses Application Default Credentials (ADC) via `gcp_auth`.

### Configuration

| Env Variable | Description |
|-------------|-------------|
| `GCP_PROJECT_ID` or `GOOGLE_CLOUD_PROJECT` | GCP project ID |
| `GOOGLE_APPLICATION_CREDENTIALS` | Path to service account JSON (optional) |

### Capabilities

- ✅ List all secrets
- ✅ Get secret metadata and labels
- ✅ Rotation (adds new secret version)
- ✅ Revocation (deletes secret)
- ⚠️ Audit via Cloud Audit Logs (not queryable from this server)

### Usage

```rust
use mcp_credentials_vault::gcp::GcpBackend;

let backend = GcpBackend::new("my-project-id".into()).await?;
```

---

## Azure Key Vault

**Feature:** `azure`

Uses Azure REST API with bearer token authentication.

### Configuration

| Env Variable | Description |
|-------------|-------------|
| `AZURE_VAULT_URL` | Key Vault URL (e.g. `https://myvault.vault.azure.net`) |
| `AZURE_ACCESS_TOKEN` | Azure AD bearer token |

### Capabilities

- ✅ List all secrets
- ✅ Get secret metadata and attributes
- ✅ Rotation (creates new secret version)
- ✅ Revocation (disables secret)
- ⚠️ Audit via Azure Monitor (not queryable from this server)

### Usage

```rust
use mcp_credentials_vault::azure::AzureBackend;

let backend = AzureBackend::new(
    "https://myvault.vault.azure.net".into(),
    "eyJ0eXAi...".into(),
);
```

---

## HashiCorp Vault

**Feature:** `hashicorp`

Connects to HashiCorp Vault's KV v2 secrets engine via HTTP API.

### Configuration

| Env Variable | Description |
|-------------|-------------|
| `VAULT_ADDR` | Vault server URL (e.g. `http://127.0.0.1:8200`) |
| `VAULT_TOKEN` | Authentication token |
| `VAULT_MOUNT` | KV v2 mount path (default: `secret`) |

### Capabilities

- ✅ List secrets (via metadata LIST)
- ✅ Get secret metadata
- ✅ Rotation (writes new KV version)
- ✅ Revocation (deletes all versions)
- ⚠️ Audit via Vault audit device (not queryable from this server)

### Usage

```rust
use mcp_credentials_vault::hashicorp::HashicorpBackend;

let backend = HashicorpBackend::new(
    "http://127.0.0.1:8200".into(),
    "hvs.CAESIG...".into(),
    None, // uses "secret" mount
);
```

---

## Implementing a Custom Backend

Implement the `VaultBackend` trait:

```rust
use async_trait::async_trait;
use mcp_credentials_vault::{VaultBackend, VaultError, types::*};

pub struct MyBackend;

#[async_trait]
impl VaultBackend for MyBackend {
    fn backend_type(&self) -> BackendType { /* ... */ }
    async fn health_check(&self) -> Result<(), VaultError> { /* ... */ }
    async fn list_credentials(&self) -> Result<Vec<Credential>, VaultError> { /* ... */ }
    async fn get_credential(&self, id: &str) -> Result<Credential, VaultError> { /* ... */ }
    async fn issue_runtime_handle(&self, id: &str, scope: &[String], ttl: u64) -> Result<RuntimeSecretHandle, VaultError> { /* ... */ }
    async fn mint_workload_token(&self, id: &str, audience: &str, ttl: u64) -> Result<WorkloadToken, VaultError> { /* ... */ }
    async fn rotate(&self, id: &str) -> Result<(), VaultError> { /* ... */ }
    async fn revoke(&self, id: &str) -> Result<(), VaultError> { /* ... */ }
    async fn audit_log(&self, id: Option<&str>, limit: usize) -> Result<Vec<AuditEvent>, VaultError> { /* ... */ }
}
```
