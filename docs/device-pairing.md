# Device Pairing Guide

Managed devices are distinct from network-discovered devices. They must be explicitly paired and receive a device-specific credential.

1. On the Windows agent PC, obtain its non-secret stable ID:

```powershell
python -m agent.windows_agent --show-device-id
```

2. As an authenticated administrator, create a short-lived pairing session bound to that ID using `POST /api/pairing/request`.
3. On the agent PC, complete pairing:

```powershell
python -m agent.windows_agent --url http://<PC-private-IPv4>:8001 --pairing-code <one-time-code>
```

4. The agent stores its device credential with the current Windows user's DPAPI key at `%LOCALAPPDATA%\CyberCommandCenter\agent\agent-token.dpapi`.
5. Start it later without the code. It sends bounded health telemetry, heartbeats, and polls only allowlisted read-only actions.

Pairing codes are hashed at rest, expire, are one-time-use, and reject a mismatched bound device ID. Revoke a device from the authenticated managed-device API if it is lost or no longer trusted.

The agent never executes shell commands, PowerShell, command strings, or arbitrary remote payloads.
