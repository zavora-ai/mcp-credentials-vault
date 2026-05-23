# Security Model

## Core Principle: Zero Secret Exposure

The Credentials Vault MCP server is designed so that **raw secret values never appear in LLM context**. This is enforced at the architecture level, not by policy alone.

## How It Works

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  LLM Agent  │────▶│  Vault MCP Server │────▶│  Vault Backend  │
│             │     │                    │     │                  │
│  Sees only: │     │  Returns only:     │     │  Stores:         │
│  - handles  │     │  - handle IDs      │     │  - actual secrets│
│  - metadata │     │  - expiry times    │     │  - raw values    │
│  - status   │     │  - scope info      │     │                  │
└─────────────┘     └──────────────────┘     └─────────────────┘
                              │
                              ▼
                    ┌──────────────────┐
                    │  Runtime Worker   │
                    │  (outside LLM)    │
                    │                    │
                    │  Resolves handle  │
                    │  to actual secret │
                    └──────────────────┘
```

## Security Layers

### 1. No Raw Secret in Response

The `VaultBackend` trait has no method that returns a secret value. `get_credential()` returns metadata only. The `Credential` struct's data never includes the secret itself.

### 2. Scoped Access

Each credential declares a `scope` — a list of actor IDs (agents, skills, MCP servers) that may access it:

```json
{
  "scope": ["agent-deploy", "mcp-github-server"]
}
```

An empty scope means unrestricted access. The `validate_secret_scope` tool checks this before access.

### 3. Time-Bounded Handles

Runtime handles expire:
- Default TTL: 300 seconds (5 minutes)
- Maximum recommended: 3600 seconds (1 hour)
- Handles cannot be renewed — a new one must be requested

### 4. Audit Trail

Every operation is logged:
- **access** — handle issued successfully
- **denied** — access blocked by scope or policy
- **rotated** — secret value changed
- **revoked** — credential disabled
- **token_minted** — workload token issued
- **scope_validated** — scope check performed

### 5. Backend Isolation

Each backend authenticates independently. Compromising one backend's credentials does not grant access to others.

## Threat Model

| Threat | Mitigation |
|--------|-----------|
| LLM exfiltrates secret from context | Impossible — secrets never enter context |
| Prompt injection requests secret | Tool returns handle, not value |
| Stolen handle used after expiry | Handles have TTL, rejected after expiry |
| Unauthorized agent accesses credential | Scope validation blocks access |
| Audit log tampering | ADK Vault logs are append-only in memory |
| Backend credential compromise | Each backend uses separate auth; revoke immediately |

## Governance Integration

In production ADK-Rust Enterprise deployments:

1. `request_runtime_secret` calls the **Governance Policy MCP** before issuing a handle
2. `rotate_credential` and `revoke_credential` require **approval gates**
3. All audit events flow to the **Session Memory MCP** for session-level tracking
4. The **MCP Registry** enforces which servers can declare credential bindings

## Recommendations

- Set `scope` on all production credentials — don't leave them open
- Use short TTLs (60–300s) for runtime handles
- Enable rotation policies on all long-lived credentials
- Monitor `denied` audit events for unauthorized access attempts
- Revoke immediately on compromise — don't wait for expiry
