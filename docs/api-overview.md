# API Overview

All API routes are under `/api`. Send `Authorization: Bearer <CCC_API_TOKEN>` for protected routes when `CCC_AUTH_ENABLED=true`.

| Area | Routes |
| --- | --- |
| Public health | `GET /api/status` |
| Dashboard | `GET /api/stats`, `/api/risk`, `/api/risk/history`, `/api/timeline` |
| Events and alerts | `GET /api/events`, `GET/PATCH/POST /api/alerts/...` |
| Network | `GET /api/devices`, `GET /api/network/scopes`, `POST /api/network/scan` |
| APK Guard | `GET /api/apk`, `POST /api/apk/scan` |
| WebSec Lab | `GET /api/websec`, `GET /api/websec/targets`, `POST /api/websec/scan` |
| HashLab | `GET /api/crypto`, `POST /api/crypto/hash`, `POST /api/crypto/verify` |
| Managed devices | `POST /api/pairing/request`, `GET/POST /api/managed-devices/...` |

Agent-only endpoints additionally require `X-Device-Id` and `X-Device-Token`. API errors use a consistent JSON envelope with `error` and `message`; tokens, pairing secrets, and database URLs are not returned.
