from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlalchemy import delete

from backend.database.session import SessionLocal, init_db
from backend.main import create_app
from backend.models import (
    Alert,
    DeviceHeartbeat,
    DeviceRiskSnapshot,
    ManagedDevice,
    PairingSession,
    RemoteAction,
    SecurityEvent,
)


def clean_phase5():
    init_db()
    db = SessionLocal()
    try:
        for model in (RemoteAction, DeviceHeartbeat, DeviceRiskSnapshot, PairingSession, ManagedDevice):
            db.execute(delete(model))
        db.execute(delete(Alert))
        db.execute(delete(SecurityEvent))
        db.commit()
    finally:
        db.close()


def test_pairing_is_one_time_and_device_token_authenticates():
    clean_phase5()
    client = TestClient(create_app())
    pairing = client.post("/api/pairing/request", json={"device_name": "Lab Agent"})
    assert pairing.status_code == 200
    code = pairing.json()["pairing_code"]
    completed = client.post(
        "/api/pairing/complete",
        json={
            "pairing_code": code,
            "device_id": "test-agent-1",
            "device_name": "Lab Agent",
            "device_type": "computer",
            "platform": "windows",
            "agent_version": "test",
            "os_info": {"system": "Windows"},
        },
    )
    assert completed.status_code == 200
    token = completed.json()["device_token"]
    assert token
    reused = client.post(
        "/api/pairing/complete",
        json={
            "pairing_code": code,
            "device_id": "test-agent-2",
            "device_name": "Second Agent",
        },
    )
    assert reused.status_code in {401, 409}
    duplicate_code = client.post("/api/pairing/request", json={"device_id": "test-agent-1"}).json()["pairing_code"]
    duplicate_device = client.post(
        "/api/pairing/complete",
        json={"pairing_code": duplicate_code, "device_id": "test-agent-1", "device_name": "Duplicate"},
    )
    assert duplicate_device.status_code == 409

    heartbeat = client.post(
        "/api/managed-devices/test-agent-1/heartbeat",
        headers={"X-Device-Id": "test-agent-1", "X-Device-Token": token},
        json={"heartbeat_id": "heartbeat-0001", "health": {"agent": "ok"}},
    )
    assert heartbeat.status_code == 200
    assert heartbeat.json()["status"] == "ACTIVE"
    duplicate = client.post(
        "/api/managed-devices/test-agent-1/heartbeat",
        headers={"X-Device-Id": "test-agent-1", "X-Device-Token": token},
        json={"heartbeat_id": "heartbeat-0001", "health": {"agent": "ok"}},
    )
    assert duplicate.status_code == 200
    assert duplicate.json()["duplicate"] is True


def test_remote_telemetry_flows_to_device_alert_risk_and_timeline():
    clean_phase5()
    client = TestClient(create_app())
    code = client.post("/api/pairing/request", json={}).json()["pairing_code"]
    token = client.post(
        "/api/pairing/complete",
        json={"pairing_code": code, "device_id": "test-agent-telemetry", "device_name": "Telemetry Agent"},
    ).json()["device_token"]
    headers = {"X-Device-Id": "test-agent-telemetry", "X-Device-Token": token}
    for index in range(3):
        response = client.post(
            "/api/managed-devices/test-agent-telemetry/telemetry",
            headers=headers,
            json={
                "telemetry_id": f"telemetry-{index:04d}",
                "event_type": "AUTH_FAILURE",
                "severity": "HIGH",
                "message": "Agent observed an authentication failure.",
                "metadata": {"source_component": "defensive-agent"},
            },
        )
        assert response.status_code == 200
    risk = client.get("/api/managed-devices/test-agent-telemetry/risk").json()
    assert risk["score"] > 0
    alerts = client.get("/api/managed-devices/test-agent-telemetry/alerts").json()["items"]
    assert alerts
    timeline = client.get("/api/timeline", params={"source": "managed_device"}).json()["items"]
    assert timeline
    assert any(item.get("metadata", {}).get("managed_device_id") == "test-agent-telemetry" for item in timeline)
    device_timeline = client.get("/api/timeline", params={"device_id": "test-agent-telemetry"}).json()["items"]
    assert device_timeline
    assert all(item.get("metadata", {}).get("managed_device_id") == "test-agent-telemetry" for item in device_timeline)


def test_revoked_device_cannot_heartbeat_or_request_actions():
    clean_phase5()
    client = TestClient(create_app())
    code = client.post("/api/pairing/request", json={}).json()["pairing_code"]
    result = client.post(
        "/api/pairing/complete",
        json={"pairing_code": code, "device_id": "test-agent-revoke", "device_name": "Revocation Agent"},
    ).json()
    token = result["device_token"]
    assert client.post("/api/managed-devices/test-agent-revoke/revoke").status_code == 200
    replacement_code = client.post("/api/pairing/request", json={"device_id": "test-agent-revoke"}).json()["pairing_code"]
    assert client.post(
        "/api/pairing/complete",
        json={"pairing_code": replacement_code, "device_id": "test-agent-revoke", "device_name": "Replacement"},
    ).status_code == 409
    headers = {"X-Device-Id": "test-agent-revoke", "X-Device-Token": token}
    heartbeat = client.post(
        "/api/managed-devices/test-agent-revoke/heartbeat",
        headers=headers,
        json={"heartbeat_id": "revoked-heartbeat"},
    )
    assert heartbeat.status_code == 401
    action = client.post(
        "/api/managed-devices/test-agent-revoke/actions",
        json={"action_type": "REQUEST_HEARTBEAT"},
    )
    assert action.status_code == 403


def test_expired_device_pairing_is_rejected():
    clean_phase5()
    client = TestClient(create_app())
    pairing = client.post("/api/pairing/request", json={}).json()
    db = SessionLocal()
    try:
        session = db.query(PairingSession).filter_by(session_id=pairing["session_id"]).one()
        session.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        db.commit()
    finally:
        db.close()
    response = client.post(
        "/api/pairing/complete",
        json={"pairing_code": pairing["pairing_code"], "device_id": "expired-agent", "device_name": "Expired"},
    )
    assert response.status_code == 410


def _pair(client: TestClient, device_id: str) -> str:
    code = client.post("/api/pairing/request", json={"device_id": device_id}).json()["pairing_code"]
    return client.post(
        "/api/pairing/complete",
        json={"pairing_code": code, "device_id": device_id, "device_name": device_id},
    ).json()["device_token"]


def test_device_isolation_offline_recovery_and_scoped_replay_ids():
    clean_phase5()
    client = TestClient(create_app())
    token_a = _pair(client, "qa-device-a")
    token_b = _pair(client, "qa-device-b")
    headers_a = {"X-Device-Id": "qa-device-a", "X-Device-Token": token_a}
    headers_b = {"X-Device-Id": "qa-device-b", "X-Device-Token": token_b}

    assert client.post(
        "/api/managed-devices/qa-device-b/heartbeat",
        headers=headers_a,
        json={"heartbeat_id": "isolation-heartbeat"},
    ).status_code == 403
    assert client.post(
        "/api/managed-devices/qa-device-a/heartbeat",
        headers={"X-Device-Id": "qa-device-a", "X-Device-Token": "wrong-token"},
        json={"heartbeat_id": "wrong-token-heartbeat"},
    ).status_code == 401

    for headers, device_id in ((headers_a, "qa-device-a"), (headers_b, "qa-device-b")):
        response = client.post(
            f"/api/managed-devices/{device_id}/telemetry",
            headers=headers,
            json={"telemetry_id": "same-id-on-two-devices", "event_type": "AGENT_NOTICE", "message": "bounded notice"},
        )
        assert response.status_code == 200
        assert response.json()["duplicate"] is False

    db = SessionLocal()
    try:
        device_a = db.query(ManagedDevice).filter_by(device_id="qa-device-a").one()
        device_a.last_seen = datetime.now(timezone.utc) - timedelta(minutes=10)
        device_a.status = "ACTIVE"
        db.commit()
    finally:
        db.close()
    inventory = client.get("/api/managed-devices").json()["items"]
    assert next(item for item in inventory if item["device_id"] == "qa-device-a")["status"] == "OFFLINE"
    recovered = client.post(
        "/api/managed-devices/qa-device-a/heartbeat",
        headers=headers_a,
        json={"heartbeat_id": "recovery-heartbeat"},
    )
    assert recovered.status_code == 200
    assert client.get("/api/managed-devices/qa-device-a/status").json()["status"] == "ACTIVE"

    db = SessionLocal()
    try:
        before = db.query(DeviceRiskSnapshot).filter_by(device_id="qa-device-a").count()
    finally:
        db.close()
    client.get("/api/managed-devices/qa-device-a/risk")
    client.get("/api/managed-devices/qa-device-a/risk")
    db = SessionLocal()
    try:
        after = db.query(DeviceRiskSnapshot).filter_by(device_id="qa-device-a").count()
    finally:
        db.close()
    assert after <= before + 1


def test_safe_action_audit_and_pairing_rate_limit():
    clean_phase5()
    client = TestClient(create_app())
    token = _pair(client, "qa-action-device")
    requested = client.post(
        "/api/managed-devices/qa-action-device/actions",
        json={"action_type": "REQUEST_SYSTEM_INFO", "requested_by": "qa"},
    )
    assert requested.status_code == 200
    action_id = requested.json()["action_id"]
    assert client.post(
        "/api/managed-devices/qa-action-device/actions",
        json={"action_type": "POWERSHELL", "requested_by": "qa"},
    ).status_code == 400
    headers = {"X-Device-Id": "qa-action-device", "X-Device-Token": token}
    pending = client.get("/api/managed-devices/qa-action-device/actions/pending", headers=headers)
    assert pending.status_code == 200
    completed = client.patch(
        f"/api/managed-devices/qa-action-device/actions/{action_id}",
        headers=headers,
        json={"status": "COMPLETED", "result_summary": "read-only status returned"},
    )
    assert completed.status_code == 200
    assert completed.json()["status"] == "COMPLETED"
    for _ in range(18):
        assert client.post(
            "/api/managed-devices/qa-action-device/actions",
            json={"action_type": "REQUEST_HEARTBEAT", "requested_by": "qa"},
        ).status_code == 200
    assert client.post(
        "/api/managed-devices/qa-action-device/actions",
        json={"action_type": "REQUEST_HEARTBEAT", "requested_by": "qa"},
    ).status_code == 429

    results = []
    for _ in range(9):
        results.append(client.post("/api/pairing/complete", json={"pairing_code": "x" * 16, "device_id": "guess-device", "device_name": "Guess"}).status_code)
    assert results[-1] == 429


def test_expired_credentials_rotation_and_malformed_telemetry_are_safe():
    clean_phase5()
    client = TestClient(create_app())
    token = _pair(client, "qa-credential-device")
    headers = {"X-Device-Id": "qa-credential-device", "X-Device-Token": token}
    db = SessionLocal()
    try:
        device = db.query(ManagedDevice).filter_by(device_id="qa-credential-device").one()
        device.credential_expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.commit()
    finally:
        db.close()
    expired = client.post(
        "/api/managed-devices/qa-credential-device/heartbeat",
        headers=headers,
        json={"heartbeat_id": "expired-credential-heartbeat"},
    )
    assert expired.status_code == 401

    rotated = client.post("/api/managed-devices/qa-credential-device/rotate-credential")
    assert rotated.status_code == 200
    new_token = rotated.json()["device_token"]
    assert client.post(
        "/api/managed-devices/qa-credential-device/heartbeat",
        headers=headers,
        json={"heartbeat_id": "old-token-heartbeat"},
    ).status_code == 401
    new_headers = {"X-Device-Id": "qa-credential-device", "X-Device-Token": new_token}
    assert client.post(
        "/api/managed-devices/qa-credential-device/heartbeat",
        headers=new_headers,
        json={"heartbeat_id": "new-token-heartbeat"},
    ).status_code == 200
    assert client.post(
        "/api/managed-devices/qa-credential-device/telemetry",
        headers=new_headers,
        json={"telemetry_id": "oversized", "event_type": "NOTICE", "message": "x", "metadata": {"data": "x" * 13000}},
    ).status_code == 413
    assert client.post(
        "/api/managed-devices/unknown-device/telemetry",
        headers={"X-Device-Id": "unknown-device", "X-Device-Token": "not-valid-token"},
        json={"telemetry_id": "unknown-telemetry", "event_type": "NOTICE", "message": "x"},
    ).status_code == 401
    malformed = client.post(
        "/api/managed-devices/qa-credential-device/telemetry",
        headers={**new_headers, "Content-Type": "application/json"},
        content="not-json",
    )
    assert malformed.status_code == 422
