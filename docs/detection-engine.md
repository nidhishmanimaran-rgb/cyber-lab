# Detection Engine

Modules create normalized `SecurityEvent` records. Detection rules then create active alerts while avoiding duplicate active alerts for the same condition.

Implemented rules:

- `NEW_DEVICE` -> MEDIUM alert.
- repeated `AUTH_FAILURE` events in 10 minutes -> HIGH alert.
- HIGH or CRITICAL `APK_SCAN_COMPLETED` -> alert.
- HIGH or CRITICAL WebSec finding -> alert.

Alerts can be acknowledged through:

```text
POST /api/alerts/{id}/acknowledge
```

The Risk Engine calculates `LAB RISK SCORE` from active alerts and recent scan risk contributions. It is a local lab score, not an official industry score.

Alerts store `rule_id` and `rule_metadata` so the dashboard/API can explain why an alert exists. Repeated authentication failures are derived from `AUTH_FAILURE` events and controlled by:

- `CCC_AUTH_FAILURE_THRESHOLD`
- `CCC_AUTH_FAILURE_WINDOW_MINUTES`
