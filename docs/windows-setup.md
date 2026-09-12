# Windows Backend Setup

## Configuration

Edit `.env` only on the local PC. Keep these production-oriented values:

```text
CCC_API_HOST=127.0.0.1
CCC_API_PORT=8001
CCC_AUTH_ENABLED=true
CCC_API_TOKEN=<generated secret>
```

Set `CCC_API_HOST=0.0.0.0` only when the dashboard or Android app must use the same trusted private Wi-Fi or private Tailscale network. A current Tailscale IPv4 address may also be used when binding only to that interface. Do not configure router port forwarding and do not bind the application to a public address.

`start.ps1` refuses an enabled-auth configuration with an empty or short token. Generate a replacement only when needed:

```powershell
python .\scripts\new_token.py
```

Update `.env` privately, restart the backend, and update the Android token.

## Operations

```powershell
.\scripts\start.ps1
.\scripts\health.ps1
.\scripts\backup.ps1
```

For Windows Firewall, allow TCP `8001` only on the required **Private** profiles. The dashboard address is `http://<PC-private-IPv4>:8001/`; for Tailscale, use the PC's current Tailscale IP or DNS name with `:8001`.
