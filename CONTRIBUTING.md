# Contributing to Credentials Vault MCP

Thank you for your interest in contributing! This server is part of the [ADK-Rust Enterprise](https://enterprise.adk-rust.com) ecosystem.

## Getting Started

1. Fork the repository
2. Clone your fork locally
3. Set up the development environment:

```bash
# Requires Rust 1.85+ (2024 edition)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup update

git clone https://github.com/zavora-ai/mcp-credentials-vault
cd mcp-credentials-vault
cargo build --features all-backends
```

## Development Workflow

### Branch Naming

- `feature/description` — New features
- `fix/description` — Bug fixes
- `docs/description` — Documentation updates
- `backend/name` — New vault backend implementations

### Running Tests

```bash
# Unit tests (no external deps)
cargo test

# All backends (requires AWS/GCP credentials)
cargo test --features all-backends
```

### Adding a New Backend

1. Create `src/my_backend.rs`
2. Implement the `VaultBackend` trait
3. Add a feature flag in `Cargo.toml`
4. Add the module to `src/lib.rs` behind `#[cfg(feature = "my-backend")]`
5. Add integration tests

### Code Standards

- Run `cargo clippy --features all-backends` before submitting
- Run `cargo fmt` for formatting
- All tools must never expose raw secrets — return handles only
- All credential access must be audit-logged

## Pull Requests

- Keep PRs focused on a single change
- Include tests for new functionality
- Update CHANGELOG.md
- Ensure CI passes

## Security

If you discover a security vulnerability, please report it via [SECURITY.md](SECURITY.md) — do not open a public issue.
