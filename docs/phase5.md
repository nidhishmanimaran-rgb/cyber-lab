# Phase 5: Managed Devices and Secure Remote Monitoring

Phase 5 extends the local Cyber Command Center with explicit, auditable device
authorization. Network discovery remains observation only. A discovered host is
not a managed device until an administrator creates a pairing session and the
device completes it.

## Architecture

The backend stores `managed_devices`, short-lived `pairing_sessions`,
`device_heartbeats`, `device_risk_snapshots`, and `remote_actions`. Existing
events, alerts, detection rules, risk snapshots, and timeline records remain the
shared security pipeline. Remote telemetry is tagged with the managed device
identity and is treated as untrusted data.

The Windows agent in `agent/windows_agent.py` reports bounded metadata only:
hostname, operating-system information, agent health, and basic network
information. It does not collect passwords, browser data, private files,
messages, keystrokes, screenshots, audio, or video. It never executes command
strings.

## Pairing and credentials

1. An authenticated administrator calls `POST /api/pairing/request`.
2. The returned pairing code expires after `CCC_PAIRING_TTL_SECONDS` and is
   returned only in that response. The backend stores only its hash.
3. The intended agent calls `POST /api/pairing/complete` with its generated
   device identity and code.
4. The code becomes unusable and the response returns a device credential once.
5. Heartbeats and telemetry use `X-Device-Id` and `X-Device-Token`.
6. Credentials expire according to `CCC_DEVICE_CREDENTIAL_TTL_DAYS`. An admin
   can rotate them or revoke the device.

The Windows agent stores its credential encrypted with the current Windows
user's DPAPI key in `%LOCALAPPDATA%\CyberCommandCenter\agent\agent-token.dpapi`.
The credential is never written as plaintext and is not logged. The storage
implementation is isolated behind `agent/credential_store.py` so another
platform-protected store can be substituted if the agent is ported.

For identity-bound pairing, first obtain the non-secret device ID from the
agent, then supply that value when the administrator creates the pairing
session:

```powershell
python -m agent.windows_agent --show-device-id
```

Start the agent from the project root after an administrator creates the
matching one-time pairing code:

```powershell
python -m agent.windows_agent --url http://192.168.1.2:8001 --pairing-code <one-time-code>
```

After pairing, the agent can start without `--pairing-code`; it sends a bounded
heartbeat and health telemetry, polls allowlisted actions, retries transient
connectivity failures with bounded backoff, and exits cleanly on Ctrl+C. The
same values can be supplied through `CCC_AGENT_URL`, `CCC_AGENT_PAIRING_CODE`,
`CCC_AGENT_DEVICE_NAME`, and `CCC_AGENT_INTERVAL_SECONDS`.

## API groups

Protected administrator routes:

- `POST /api/pairing/request`
- `GET /api/managed-devices`
- `GET /api/managed-devices/{device_id}`
- `GET /api/managed-devices/{device_id}/status`
- `GET /api/managed-devices/{device_id}/risk`
- `GET /api/managed-devices/{device_id}/events`
- `GET /api/managed-devices/{device_id}/alerts`
- `POST /api/managed-devices/{device_id}/revoke`
- `POST /api/managed-devices/{device_id}/rotate-credential`
- `GET/POST /api/managed-devices/{device_id}/actions`

Device-authenticated routes:

- `POST /api/pairing/complete`
- `POST /api/managed-devices/{device_id}/heartbeat`
- `POST /api/managed-devices/{device_id}/telemetry`
- `GET /api/managed-devices/{device_id}/actions/pending`
- `PATCH /api/managed-devices/{device_id}/actions/{action_id}`

Remote action types are allowlisted: heartbeat, system information, network
status, security status, local security scan request, and telemetry refresh.
There is no arbitrary shell or PowerShell command endpoint.

## Risk, alerts, and offline state

Device risk is calculated separately from the global lab risk. Remote events are
excluded from the global repeated-event signal so the same event is not counted
twice. Device alerts can still contribute through the normal alert engine.

Heartbeats mark a paired device `ACTIVE`. After
`CCC_DEVICE_OFFLINE_AFTER_SECONDS` without a heartbeat it becomes `OFFLINE` and
the backend records “device is unreachable”; offline does not mean compromised.
The next valid heartbeat returns it to `ACTIVE`. Transition events and alerts
are deduplicated by the existing alert engine. A bounded FastAPI lifespan task
checks stale heartbeats at the configured interval and stops cleanly during
backend shutdown.

## Secure remote access

LAN mode:

```text
Android -> private home Wi-Fi -> PC:8001
```

Remote mode:

```text
Android -> private encrypted tunnel -> PC/backend -> paired agent
```

Set `CCC_PRIVATE_TUNNEL_ENDPOINT` only for a private tunnel integration. The
core application does not assume a tunnel vendor and never opens or requests a
public FastAPI port. Do not forward port 8001 to the public internet.

The test suite includes a **Private remote-access integration test** using a
local in-process boundary named `private-tunnel.local`. It verifies admin
authentication, device authentication, authorization, telemetry, alerts,
timeline, safe actions, audit events, and revocation without exposing a port or
claiming that a real VPN works. A real third-party VPN remains an external
validation item.

## Audit and failure handling

Pairing, failed pairing, pairing completion, authentication failures, credential
rotation, revocation, heartbeats, telemetry, and remote action completion are
represented by security events. Tokens, pairing codes, private keys, passwords,
and personal data are not written to application logs. Payload limits,
identity matching, replay checks for heartbeat and telemetry IDs, rate limits,
credential expiry, and revocation protect the device API.

## Validation

Run the full suite from the project root:

```powershell
python -m pytest
```

The Phase 5 tests cover one-time pairing, expiry, device authentication,
heartbeat deduplication, telemetry to alert/risk/timeline flow, revocation,
credential protection, automatic offline monitoring, private remote-access
integration, and regression coverage for the existing modules.

Android continues to use the existing UI and token settings. The More page now
shows explicitly paired devices, status, risk, last seen, and agent version.
The default LAN URL is configured in `MainActivity.kt`; change it in Settings
for another private-LAN address.

## External validation checklist

Physical Android:

- [ ] Device connected and authorized in ADB
- [ ] Latest debug APK installed
- [ ] Backend reachable over private LAN
- [ ] Valid and invalid token states checked
- [ ] Managed devices, risk, alerts, timeline, and safe actions checked

Real private tunnel:

- [ ] Private tunnel provider configured
- [ ] Android reaches the backend through the tunnel
- [ ] Device authentication and authorization checked
- [ ] Telemetry, alerts, and revocation checked through the tunnel

The local private remote-access integration test is automated and passing, but
it is not a real VPN test.

## Limitations

- The Windows agent is a lightweight reference agent, not a signed enterprise
  service.
- No third-party tunnel is bundled; private tunnel installation and firewall
  policy remain operator responsibilities.
- Android physical-device validation requires Android Studio/ADB and a device;
  backend tests do not claim that hardware validation.
- SQLite and in-memory rate limiting are appropriate for this personal lab, not
  a multi-user production deployment.
