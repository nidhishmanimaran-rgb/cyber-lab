# Cyber Command Center v1.0.0

Cyber Command Center is a local, defensive cybersecurity lab and private SOC-style dashboard. It combines FastAPI, SQLite, the Windows reference agent, a web dashboard, and an Android dashboard into one local-first product.

This project is intended only for personal cybersecurity education, defensive monitoring, authorized testing, local security research, deliberately vulnerable lab environments, and APK files supplied by the user. It must not be used to scan arbitrary internet infrastructure or compromise systems.

## Architecture

```text
Samsung M02 browser/app
        |
        | local Wi-Fi REST API
        v
Windows PC backend
        |
        +-- FastAPI API
        +-- SQLite database
        +-- Network Monitor
        +-- APK Guard
        +-- WebSec Lab
        +-- HashLab
        +-- Detection Engine
```

Release structure:

```text
backend/
  api/
  core/
  database/
  models/
  services/
  detection/
  network/
  apk/
  websec/
  crypto/
  alerts/
  logging/
frontend/
android/
lab/
tests/
docs/
scripts/
```

## Requirements

- Windows PC
- Python 3.11+
- Local network access only for the lab

## Quick Start

```powershell
.\scripts\setup.ps1
```

The setup script creates a local virtual environment, installs the pinned dependency ranges, creates a private `.env` with authentication enabled when needed, initializes the database additively, and verifies integrity.

## Configuration

Copy `.env.example` to `.env` when you want local overrides.

Important settings:

- `CCC_API_HOST`: API bind host. Defaults to `127.0.0.1`.
- `CCC_API_PORT`: API port. Defaults to `8001`.
- `CCC_DATABASE_URL`: SQLite database URL.
- `CCC_AUTH_ENABLED`: Keep `true` for normal LAN/private operation.
- `CCC_API_TOKEN`: API key value used with the `Authorization: Bearer ...` header. Legacy `x-api-key` is still accepted for compatibility.
- `CCC_NETWORK_SCAN_MAX_HOSTS`: Maximum IPv4 hosts checked per conservative network scan.
- `CCC_AUTHORIZED_NETWORK_RANGES`: Optional extra network CIDR ranges for monitoring.
- `CCC_AUTHORIZED_SCAN_TARGETS`: WebSec allowlist for local/private lab targets.
- `CCC_CORS_ALLOWED_ORIGINS`: Browser origins allowed to call the API.

Do not commit `.env` or secrets.

Generate a new local token with:

```powershell
python .\scripts\new_token.py
```

## Start Backend

```powershell
.\scripts\start.ps1
```

Then open:

```text
http://127.0.0.1:8001/
http://127.0.0.1:8001/api/status
```

The backend binds to localhost by default. Do not port-forward it to the public internet. Run `./scripts/health.ps1` after startup to perform the public health check.

To open the dashboard from a phone on the same trusted Wi-Fi, set `CCC_API_HOST=0.0.0.0` in `.env`, restart the backend, find the PC's local IPv4 address, then browse to:

```text
http://YOUR_PC_LOCAL_IP:8001/
```

## Release Documentation

- [Installation](docs/installation.md)
- [Windows setup and backend operations](docs/windows-setup.md)
- [Android setup](docs/android-app.md)
- [Device pairing guide](docs/device-pairing.md)
- [Private remote access guide](docs/remote-access.md)
- [Database backup and restore](docs/database-backup-restore.md)
- [Security model](docs/security-model.md)
- [API overview](docs/api-overview.md)
- [Architecture](docs/architecture.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Release notes](docs/release-notes.md)

## API

Phase 1 provides:

```text
GET /api/status
```

The response reports service status, database connectivity, record counts, and auth state. `GET /api/status` is public; all operational and management endpoints require authentication when `CCC_AUTH_ENABLED=true`.

Implemented APIs include:

```text
/api/devices
/api/events
/api/alerts
/api/stats
/api/settings
/api/risk
/api/network/scan
/api/apk/scan
/api/websec/scan
/api/crypto/hash
/api/crypto/verify
```

History/status endpoints also exist at `/api/apk`, `/api/websec`, and `/api/crypto`.

## Testing

```powershell
python -m pytest
```

Current tests cover:

- `/api/status`
- API key enforcement when auth is enabled
- Initial database model persistence
- Dashboard stats, events, alerts, and safe settings output
- Network, APK Guard, WebSec, HashLab, detection, and risk MVP behavior
- CORS, auth-failure alerting, device service summaries, and rule metadata

## Local Lab Modules

- Network Monitor: `/#network`
- APK Guard: `/#apk`
- WebSec Lab: `/#websec`
- HashLab: `/#hashlab`
- Alerts: `/#alerts`
- Events: `/#events`

Start the deliberately vulnerable local WebSec lab with:

```powershell
python lab\vulnerable-web-app\app.py
```

The Android Kotlin project is in `android/CyberCommandCenter/`.

## Security Model

- Local-first backend.
- No public internet exposure by default.
- No plaintext password storage.
- Uploaded APKs are statically analyzed only and never executed.
- WebSec scanning is restricted to localhost, private addresses, or explicit allowlisted targets.
- No destructive actions, malware behavior, persistence mechanisms, credential theft, or unauthorized exploitation.

Phase 5 managed-device architecture and security procedures are documented in
[`docs/phase5.md`](docs/phase5.md). Managed devices require explicit pairing,
device authentication, heartbeat, revocation, and allowlisted read-only remote
actions. Never expose FastAPI port 8001 directly to the public internet.

## Limitations

Network discovery depends on Windows, router, firewall, ARP, and whether devices answer ping. The Android project includes a Gradle wrapper and builds locally; physical-device and real private-tunnel validation remain operator tasks.
