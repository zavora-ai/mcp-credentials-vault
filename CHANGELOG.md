# Changelog

## [1.1.0] - 2025-05-24

### Added
- HealthCheck trait implementation for registry monitoring
- `mcp-server.toml` manifest for ADK registry onboarding
- Structured tracing with `tracing-subscriber` (env-filter)

### Changed
- Edition upgraded to Rust 2024
- Added `adk-mcp-sdk` HealthCheck integration


All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-05-23

### Added

- **6 pluggable vault backends** — HashiCorp Vault (KV v2), AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, Internal ADK Vault, ADK-Rust Enterprise Platform API
- **8 MCP tools** — `list_credentials`, `get_credential_metadata`, `request_runtime_secret`, `request_workload_token`, `rotate_credential`, `revoke_credential`, `audit_credential_access`, `validate_secret_scope`
- **ADK Platform backend** — delegates to ADK-Rust Enterprise Platform REST API for centralized credential management
- **Zero secret exposure** — no raw secrets ever reach LLM context; only handles and short-lived tokens
- **Full audit logging** — every access, denial, rotation, and revocation event recorded
- **Scope validation** — verify whether an agent, skill, or MCP server is authorized for a credential
- **Runtime secret handles** — time-bounded, scope-limited references resolved outside LLM context
- **Workload identity tokens** — OIDC/JWT minting for service-to-service auth
- **Credential rotation** — automated rotation through each backend's native mechanism
- **Feature-flagged backends** — compile only the backends you need (`hashicorp`, `aws`, `gcp`, `azure`, `adk-vault`, `adk-platform`)
- **ADK-Rust Enterprise SDK integration** — `mcp-server.toml` manifest, `HealthCheck` trait, risk class annotations
- **rmcp 1.7** — latest MCP protocol SDK with `#[tool_router(server_handler)]` pattern
- **Registry-ready** — ships with `mcp-server.toml` for automatic ADK-Rust Enterprise registry onboarding
- **Auto-detection** — backends activate based on environment variables present at startup
- **MCP client support** — installation docs for Claude, Kiro, Codex, Cursor, Windsurf, Antigravity, Open Code
