from dataclasses import replace

from fastapi.testclient import TestClient
from sqlalchemy import delete

from backend.core.config import get_settings
from backend.database.session import SessionLocal
from backend.main import create_app
from backend.models import Alert, DeviceHeartbeat, DeviceRiskSnapshot, ManagedDevice, PairingSession, RemoteAction, SecurityEvent


def _clear_managed_test_data():
    db = SessionLocal()
    try:
        for model in (RemoteAction, DeviceHeartbeat, DeviceRiskSnapshot, PairingSession, ManagedDevice, Alert, SecurityEvent):
            db.execute(delete(model))
        db.commit()
    finally:
        db.close()


def test_private_remote_access_integration_boundary():
    """Local harness for a private boundary; this is not a third-party VPN test."""
    _clear_managed_test_data()
    settings = replace(get_settings(), auth_enabled=True, api_token="qa-admin-token")
    admin = {"Authorization": "Bearer qa-admin-token"}
    with TestClient(create_app(settings), base_url="http://private-tunnel.local") as client:
        assert client.get("/api/managed-devices").status_code == 401
        pairing = client.post("/api/pairing/request", headers=admin, json={"device_id": "tunnel-device"})
        assert pairing.status_code == 200
        token = client.post(
            "/api/pairing/complete",
            json={"pairing_code": pairing.json()["pairing_code"], "device_id": "tunnel-device", "device_name": "Tunnel Device"},
        ).json()["device_token"]
        device_headers = {"X-Device-Id": "tunnel-device", "X-Device-Token": token}
        assert client.post(
            "/api/managed-devices/tunnel-device/heartbeat",
            headers=device_headers,
            json={"heartbeat_id": "tunnel-heartbeat"},
        ).status_code == 200
        for index in range(3):
            response = client.post(
                "/api/managed-devices/tunnel-device/telemetry",
                headers=device_headers,
                json={"telemetry_id": f"tunnel-telemetry-{index}", "event_type": "AUTH_FAILURE", "severity": "HIGH", "message": "controlled remote test event"},
            )
            assert response.status_code == 200
        assert client.get("/api/managed-devices/tunnel-device/risk", headers=admin).status_code == 200
        assert client.get("/api/managed-devices/tunnel-device/alerts", headers=admin).json()["items"]
        assert client.get("/api/timeline", headers=admin, params={"device_id": "tunnel-device"}).json()["items"]
        action = client.post("/api/managed-devices/tunnel-device/actions", headers=admin, json={"action_type": "REQUEST_HEARTBEAT"})
        assert action.status_code == 200
        assert client.get("/api/managed-devices/tunnel-device/actions/pending", headers=device_headers).status_code == 200
        assert client.patch(
            f"/api/managed-devices/tunnel-device/actions/{action.json()['action_id']}",
            headers=device_headers,
            json={"status": "COMPLETED", "result_summary": "local private boundary test"},
        ).status_code == 200
        assert client.post("/api/managed-devices/tunnel-device/revoke", headers=admin).status_code == 200
        assert client.post(
            "/api/managed-devices/tunnel-device/telemetry",
            headers=device_headers,
            json={"telemetry_id": "after-revoke", "event_type": "NOTICE", "message": "must reject"},
        ).status_code == 401
        events = client.get("/api/events", headers=admin, params={"source": "managed_device", "limit": 100}).json()["items"]
        event_types = {item["event_type"] for item in events}
        assert {"DEVICE_PAIRED", "REMOTE_ACTION_REQUESTED", "REMOTE_ACTION_COMPLETED", "DEVICE_REVOKED"} <= event_types
