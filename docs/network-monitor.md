# Network Monitor

The Network Monitor performs conservative discovery for private or explicitly authorized IPv4 ranges only.

Safety controls:

- Public CIDR ranges are rejected unless explicitly configured.
- Default discovery is limited by `CCC_NETWORK_SCAN_MAX_HOSTS`.
- Discovery uses one ping attempt per host and reads the local ARP table.
- A small bounded service snapshot checks common local ports only.
- Scan operations are rate limited at the API layer and return clean errors when the lab is under load.
- No exploitation, login attempts, packet crafting, or public internet scanning is implemented.

Configuration:

- `CCC_NETWORK_MONITOR_INTERVAL_SECONDS=60`
- `CCC_NETWORK_SCAN_MAX_HOSTS=64`
- `CCC_AUTHORIZED_NETWORK_RANGES=`
- `CCC_CORS_ALLOWED_ORIGINS=http://127.0.0.1:8001,http://localhost:8001`

Dashboard:

- Open `/#network`.
- Select a detected or configured scope.
- Press `Refresh Scan`.
- Use the Known/Unknown button in the device table to mark trusted devices.

New devices create one `NEW_DEVICE` security event and a MEDIUM alert. Existing devices are updated without duplicate new-device events.
