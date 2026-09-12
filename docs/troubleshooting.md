# Troubleshooting

Backend will not start:

- Confirm Python 3.11+ is installed.
- Run `.\scripts\setup.ps1`.
- Check whether the port is already in use.

Dashboard cannot reach API:

- Confirm the backend is running.
- Open `http://127.0.0.1:8001/api/status`.
- If auth is enabled, save the API token in Settings and send it as `Authorization: Bearer <token>`.
- If accessing from a separate frontend origin, add it to `CCC_CORS_ALLOWED_ORIGINS`.

Phone cannot connect:

- Set `CCC_API_HOST=0.0.0.0`.
- Use the PC private IPv4 address, such as `192.168.1.7`.
- Keep phone and PC on the same Wi-Fi.
- Allow Windows Firewall only for private networks.
- Make sure the Android app backend URL uses the PC LAN address, not `127.0.0.1`.

Need a fresh token?

- Run `python .\scripts\new_token.py`.

Network scan finds nothing:

- Try a smaller authorized CIDR.
- Confirm devices respond to ping or appear in ARP.
- Keep `CCC_NETWORK_SCAN_MAX_HOSTS` modest.

WebSec scan rejected:

- Use localhost, a private IP, or add the target to `CCC_AUTHORIZED_SCAN_TARGETS`.

APK scan rejected:

- Confirm the file is a ZIP-format APK with `AndroidManifest.xml`.
- Confirm the filename ends with `.apk`.
