# Security Model

Cyber Command Center is private, local-first defensive software. It is not an internet-facing service.

- API authentication uses a locally stored bearer token and constant-time comparison.
- `/api/status` is public for connectivity checks; operational and management routes are protected when authentication is enabled.
- CORS is allowlisted and never wildcarded by default.
- Admin pairing sessions are short-lived, one-time, and may be bound to a stable device ID.
- Device credentials are stored as hashes on the backend and protected with Windows DPAPI in the reference agent.
- Device heartbeat and telemetry endpoints require both device ID and device credential, enforce replay protection, payload validation, expiry, revocation, and rate limits.
- Remote actions use a strict allowlist. There is no arbitrary command, shell, or PowerShell execution endpoint.
- APKs are static-analysis inputs only; they are never run.
- WebSec is constrained to authorized local/private targets.
- Structured logs redact credentials, tokens, passwords, pairing codes, and verifiers.
- SQLite schema changes are additive; backup, integrity checking, and explicit restore tooling avoid automatic data loss.

Use private Wi-Fi or a private encrypted tunnel. Never publish port `8001` through port forwarding or a public reverse proxy.
