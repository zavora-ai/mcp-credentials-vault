# Credentials Vault MCP Server

[![Crates.io](https://img.shields.io/crates/v/mcp-credentials-vault.svg)](https://crates.io/crates/mcp-credentials-vault)
[![Docs.rs](https://docs.rs/mcp-credentials-vault/badge.svg)](https://docs.rs/mcp-credentials-vault)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![ADK-Rust Enterprise](https://img.shields.io/badge/ADK--Rust-Enterprise-purple.svg)](https://enterprise.adk-rust.com)

Scoped, auditable credential access for [ADK-Rust Enterprise](https://enterprise.adk-rust.com) agents. Provides 8 MCP tools over 5 pluggable vault backends — **never exposes raw secrets to LLM context**.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    MCP Agents / Skills                    │
└────────────────────────────┬────────────────────────────┘
                             │ MCP Protocol (stdio / HTTP)
┌────────────────────────────▼────────────────────────────┐
│              Credentials Vault MCP Server                 │
│                                                          │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌───────────┐  │
│  │list_creds│ │request_  │ │rotate_   │ │audit_     │  │
│  │get_meta  │ │runtime   │ │revoke    │ │validate   │  │
│  │          │ │token     │ │          │ │scope      │  │
│  └──────────┘ └──────────┘ └──────────┘ └───────────┘  │
│                                                          │
│  ┌────────────────── VaultBackend Trait ──────────────┐  │
│  │                                                    │  │
│  │  HashiCorp │ AWS Secrets │ GCP Secret │ Azure Key  │  │
│  │  Vault     │ Manager    │ Manager    │ Vault      │  │
│  │            │            │            │            │  │
│  │                    ADK Vault (internal)            │  │
│  └────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────┘
```

## Key Principles

- **Zero secret exposure** — raw secrets never reach LLM context. Tools return handles and short-lived tokens only.
- **Scoped access** — credentials declare which agents, skills, and MCP servers can use them.
- **Full audit trail** — every access, denial, rotation, and revocation is logged.
- **Pluggable backends** — use one or many vault backends simultaneously.
- **Registry-ready** — ships with `mcp-server.toml` for automatic ADK-Rust Enterprise onboarding.

## Tools

| Tool | Purpose | Risk Class |
|------|---------|------------|
| `list_credentials` | List credential metadata (never raw values) | Read-only |
| `get_credential_metadata` | Inspect owner, scope, expiry, rotation, risk | Read-only |
| `request_runtime_secret` | Issue scoped runtime handle after policy checks | Identity/Security |
| `request_workload_token` | Mint short-lived OIDC/workload identity token | Identity/Security |
| `rotate_credential` | Rotate secret through approved workflow | Identity/Security |
| `revoke_credential` | Disable compromised or expired credential | Identity/Security |
| `audit_credential_access` | Retrieve access/denial/rotation audit events | Read-only |
| `validate_secret_scope` | Check if an actor can use a credential | Read-only |

## Backends

| Backend | Feature Flag | Use Case |
|---------|-------------|----------|
| HashiCorp Vault | `hashicorp` | Self-hosted, KV v2, dynamic secrets |
| AWS Secrets Manager | `aws` | AWS-native workloads |
| GCP Secret Manager | `gcp` | GCP-native workloads |
| Azure Key Vault | `azure` | Azure-native workloads |
| ADK Vault | `adk-vault` | Platform-managed credentials (default) |

## Quick Start

### Installation

```toml
[dependencies]
mcp-credentials-vault = { version = "1.0", features = ["all-backends"] }
```

Or select specific backends:

```toml
[dependencies]
mcp-credentials-vault = { version = "1.0", features = ["aws", "gcp"] }
```

### Running as MCP Server

```rust
use mcp_credentials_vault::{adk_vault::AdkVaultBackend, server::CredentialsVaultServer};
use rmcp::{ServiceExt, transport::stdio};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let backend = AdkVaultBackend::new(Some("./credentials.json".into()));
    let server = CredentialsVaultServer::new(vec![Box::new(backend)]);
    let service = server.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
```

### Multi-backend Configuration

```rust
use mcp_credentials_vault::{
    adk_vault::AdkVaultBackend,
    aws::AwsBackend,
    gcp::GcpBackend,
    server::CredentialsVaultServer,
};

let server = CredentialsVaultServer::new(vec![
    Box::new(AdkVaultBackend::new(None)),
    Box::new(AwsBackend::new(Some("us-east-1".into())).await),
    Box::new(GcpBackend::new("my-project".into()).await?),
]);
```

## Configuration

### Environment Variables

| Variable | Backend | Purpose |
|----------|---------|---------|
| `VAULT_ADDR` | HashiCorp | Vault server URL |
| `VAULT_TOKEN` | HashiCorp | Authentication token |
| `AWS_REGION` | AWS | AWS region |
| `AWS_ACCESS_KEY_ID` | AWS | AWS credentials (or use IAM role) |
| `GCP_PROJECT_ID` | GCP | GCP project ID |
| `AZURE_VAULT_URL` | Azure | Key Vault URL |
| `AZURE_ACCESS_TOKEN` | Azure | Azure AD token |

### MCP Server Manifest

The server ships with `mcp-server.toml` for ADK-Rust Enterprise registry onboarding:

```toml
server_id = "mcp_credentials_vault"
display_name = "Credentials Vault MCP"
version = "1.0.0"
domain = "platform"
risk_level = "critical"
writes_allowed = "gated"
transports = ["stdio", "streamable_http"]
governance_gates = ["policy_evaluation_required", "audit_all_access"]
```

## Security Model

```
Agent requests credential → Scope validation → Policy check → Handle issued
                                                                    │
                                                                    ▼
                                                    Runtime worker resolves
                                                    handle to actual secret
                                                    (outside LLM context)
```

1. **Agents never see raw secrets** — only handles with expiry and scope
2. **Scope enforcement** — credentials declare allowed actors
3. **Audit everything** — access, denials, rotations, revocations
4. **Short-lived tokens** — workload tokens expire (default 5 min for runtime, 1 hour for workload)
5. **Governance gates** — `rotate` and `revoke` require approval in production

## Testing

```bash
# Build with all backends
cargo build --features all-backends

# Run tests (ADK Vault — no external deps)
cargo test

# Run with real backends (requires credentials)
cargo test --features all-backends

# Run the integration test binary
cargo run --features all-backends
```

## Documentation

| Document | Description |
|----------|-------------|
| [API Reference](https://docs.rs/mcp-credentials-vault) | Full Rust API documentation |
| [CHANGELOG.md](CHANGELOG.md) | Version history |
| [mcp-server.toml](mcp-server.toml) | Registry manifest |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Development guidelines |
| [SECURITY.md](SECURITY.md) | Vulnerability reporting |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

## Contributors

<!-- ALL-CONTRIBUTORS-LIST:START -->
| [<img src="https://github.com/jkmaina.png" width="80px;" alt=""/><br /><sub><b>James Karanja Maina</b></sub>](https://github.com/jkmaina) |
|:---:|
<!-- ALL-CONTRIBUTORS-LIST:END -->

## License

Apache-2.0 — see [LICENSE](LICENSE) for details.

---

Part of the [ADK-Rust Enterprise](https://enterprise.adk-rust.com) MCP server ecosystem.

Built with ❤️ by [Zavora AI](https://zavora.ai)
