# WebSec Lab

The local vulnerable app lives at `lab/vulnerable-web-app/`.

Start it with:

```powershell
python lab\vulnerable-web-app\app.py
```

Then scan:

```text
http://127.0.0.1:8000/
```

The scanner only allows localhost, private hosts, or configured authorized targets. Hostnames must resolve only to private or loopback addresses unless explicitly allowlisted. URLs with embedded credentials are rejected, and redirects are not followed. It checks for missing security headers, weak cookie flags, and simple unsafe-configuration hints. It is not a general exploitation platform.

Configuration:

- `CCC_AUTHORIZED_SCAN_TARGETS=http://127.0.0.1:8000,http://localhost:8000`
