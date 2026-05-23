# API Reference

## Tools

### list_credentials

List credential metadata across all configured backends. Never exposes raw secret values.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `backend` | string | No | Filter by backend type (`aws`, `gcp`, `azure`, `hashicorp`, `adk_vault`) |
| `owner` | string | No | Filter by credential owner |

**Returns:** Array of `CredentialHandle` objects.

**Example:**
```json
{
  "id": "vault://my-api-key",
  "display_name": "My API Key",
  "status": "active",
  "owner": "platform",
  "scope": ["agent-1", "mcp-github"],
  "backend": "aws",
  "risk_level": "medium",
  "expires_at": null,
  "last_rotated": "2026-05-23T10:00:00Z",
  "rotation_policy": {
    "interval_days": 90,
    "auto_rotate": true,
    "notify_before_days": 7
  }
}
```

---

### get_credential_metadata

Inspect a single credential's full metadata.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `credential_id` | string | Yes | Credential ID (e.g. `vault://my-api-key`) |

**Returns:** Single `CredentialHandle` object.

---

### request_runtime_secret

Issue a scoped, time-bounded runtime handle. The actual secret is resolved by the runtime worker **outside LLM context**.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `credential_id` | string | Yes | Credential to access |
| `scope` | string[] | No | Scopes the handle is valid for |
| `ttl_seconds` | integer | No | Handle lifetime (default: 300) |

**Returns:**
```json
{
  "handle_id": "84ccb128-57c5-4d48-8061-5e4996289841",
  "credential_id": "vault://my-api-key",
  "expires_at": "2026-05-23T10:10:00Z",
  "scope": ["kiro-agent"]
}
```

**Security:** The handle is a reference, not the secret. Runtime workers resolve it via a separate secure channel.

---

### request_workload_token

Mint a short-lived OIDC or workload identity token for service-to-service authentication.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `credential_id` | string | Yes | Credential backing the token |
| `audience` | string | Yes | Token audience (e.g. `https://api.example.com`) |
| `ttl_seconds` | integer | No | Token lifetime (default: 3600) |

**Returns:**
```json
{
  "token_id": "542e24cc-dbf3-4b68-82c6-9e35aa7c2d97",
  "credential_id": "vault://my-service-account",
  "token_type": "gcp-identity",
  "expires_at": "2026-05-23T11:00:00Z",
  "audience": "https://api.example.com"
}
```

---

### rotate_credential

Rotate a credential's secret value through the backend's native rotation mechanism.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `credential_id` | string | Yes | Credential to rotate |

**Returns:** Success message or error.

**Governance:** Requires approval in production environments.

---

### revoke_credential

Disable a compromised or expired credential immediately.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `credential_id` | string | Yes | Credential to revoke |
| `reason` | string | No | Reason for revocation (audit trail) |

**Returns:** Confirmation with reason.

**Governance:** Requires approval in production environments.

---

### audit_credential_access

Retrieve audit events for credential access, denials, rotations, and revocations.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `credential_id` | string | No | Filter by credential (all if omitted) |
| `limit` | integer | No | Max events to return (default: 50) |

**Returns:** Array of `AuditEvent` objects, newest first.

```json
{
  "event_id": "3be93aa6-43cc-4a1c-9600-2c93c4290426",
  "credential_id": "vault://demo-api-key",
  "action": "access",
  "actor": "system",
  "timestamp": "2026-05-23T10:06:17Z",
  "outcome": "success",
  "reason": null
}
```

**Actions:** `access`, `denied`, `rotated`, `revoked`, `token_minted`, `scope_validated`

---

### validate_secret_scope

Check whether a specific actor (agent, skill, or MCP server) is authorized to use a credential.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `credential_id` | string | Yes | Credential to check |
| `actor` | string | Yes | Actor ID (agent, skill, or MCP server) |

**Returns:**
```json
{
  "credential_id": "vault://my-api-key",
  "actor": "mcp-github-server",
  "allowed": true,
  "scope": ["mcp-github-server", "agent-deploy"],
  "status": "active"
}
```

**Logic:** If `scope` is empty, all actors are allowed. Otherwise, the actor must be in the scope list.

---

## Data Types

### CredentialStatus

| Value | Meaning |
|-------|---------|
| `active` | Credential is usable |
| `expired` | Past expiry date |
| `revoked` | Manually disabled |
| `rotating` | Rotation in progress |

### RiskLevel

| Value | Description |
|-------|-------------|
| `low` | Non-sensitive, development credentials |
| `medium` | Standard API keys and service accounts |
| `high` | Production database passwords, signing keys |
| `critical` | Root credentials, master keys |

### BackendType

| Value | Backend |
|-------|---------|
| `hashicorp` | HashiCorp Vault KV v2 |
| `aws` | AWS Secrets Manager |
| `gcp` | GCP Secret Manager |
| `azure` | Azure Key Vault |
| `adk_vault` | Internal ADK Vault |

### AuditAction

| Value | Trigger |
|-------|---------|
| `access` | Runtime handle issued |
| `denied` | Access blocked by scope/policy |
| `rotated` | Secret value rotated |
| `revoked` | Credential disabled |
| `token_minted` | Workload token issued |
| `scope_validated` | Scope check performed |
