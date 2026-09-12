# Architecture

Cyber Command Center v1.0.0 is a local defensive lab. The Windows PC runs FastAPI, SQLite, scanners, detection rules, the risk engine, and the lightweight managed-device agent. The web dashboard and Android app are clients.

Flow:

```text
Network / APK / WebSec / Managed Agent / Auth / HashLab
  -> normalized security events
  -> detection rules
  -> alerts
  -> lab risk score
  -> web dashboard and Android dashboard
```

The backend is local-first and binds to `127.0.0.1` by default. Use `CCC_API_HOST=0.0.0.0` only on a trusted private Wi-Fi network.

Release configuration enables authentication. Operational routes require `Authorization: Bearer <token>`; `GET /api/status` remains public for connectivity checks.

Core endpoints:

- `GET /api/status`
- `GET /api/stats`
- `GET /api/risk`
- `GET /api/devices`
- `POST /api/network/scan`
- `POST /api/apk/scan`
- `POST /api/websec/scan`
- `POST /api/crypto/hash`
- `POST /api/crypto/verify`
- `GET /api/events`
- `GET /api/alerts`

Near real-time updates are implemented with dashboard polling every 15 seconds on live data pages. This keeps the MVP simple while preserving the event-to-alert-to-dashboard flow.

CORS is configured from `CCC_CORS_ALLOWED_ORIGINS` and is not wildcarded by default.

Managed-device credentials are hashed in SQLite and protected by DPAPI in the Windows reference agent. A FastAPI lifespan monitor marks stale devices offline, while the next valid heartbeat records recovery. Database initialization uses additive schema changes and validates SQLite integrity at startup.
