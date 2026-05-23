# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅        |

## Reporting a Vulnerability

This is a security-critical server that handles credential access. We take vulnerabilities seriously.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please report via:

- Email: security@zavora.ai
- Subject: `[mcp-credentials-vault] Security Vulnerability`

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and provide a timeline for resolution.

## Security Design

This server is designed with defense-in-depth:

1. **No raw secret exposure** — tools return handles, never secret values
2. **Scope enforcement** — credentials declare allowed actors
3. **Audit logging** — all access attempts are recorded
4. **Short-lived tokens** — runtime handles expire quickly
5. **Backend isolation** — each backend authenticates independently
