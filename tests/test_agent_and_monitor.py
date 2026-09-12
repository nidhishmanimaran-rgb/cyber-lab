import os
import time
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete

from agent.credential_store import SecretStoreError, WindowsDpapiStore
from agent.windows_agent import WindowsAgent
from backend.core.config import get_settings
from backend.database.session import SessionLocal
from backend.main import create_app
from backend.models import Alert, DeviceHeartbeat, DeviceRiskSnapshot, ManagedDevice, PairingSession, RemoteAction, SecurityEvent


class MemoryStore:
    def __init__(self):
        self.value = None

    def load(self):
        return self.value

    def save(self, value):
        self.value = value

    def delete(self):
        self.value = None


def test_agent_credential_lifecycle_and_clean_shutdown(tmp_path):
    store = MemoryStore()
    agent = WindowsAgent("http://127.0.0.1:9", state_dir=tmp_path, secret_store=store)
    with pytest.raises(RuntimeError):
        agent.token()
    store.save("device-secret")
    assert agent.token() == "device-secret"
    store.delete()
    with pytest.raises(RuntimeError):
        agent.token()
    agent.stop()
    assert agent.stop_event.is_set()


def test_agent_device_identity_is_stable_and_retries_transient_failures(tmp_path):
    store = MemoryStore()
    agent = WindowsAgent("http://127.0.0.1:9", state_dir=tmp_path, secret_store=store)
    assert WindowsAgent("http://127.0.0.1:9", state_dir=tmp_path, secret_store=store).device_id() == agent.device_id()

    attempts = []

    def run_once():
        attempts.append(True)
        if len(attempts) == 1:
            raise OSError("temporary connection failure")
        agent.stop()

    agent.run_once = run_once  # type: ignore[method-assign]
    agent.run_forever(interval_seconds=10)
    assert len(attempts) == 2


@pytest.mark.skipif(os.name != "nt", reason="Windows DPAPI is only available on Windows")
def test_windows_dpapi_store_does_not_write_plaintext(tmp_path):
    path = tmp_path / "agent-token.dpapi"
    store = WindowsDpapiStore(path)
    store.save("protected-device-secret")
    assert path.exists()
    assert b"protected-device-secret" not in path.read_bytes()
    assert store.load() == "protected-device-secret"
    store.delete()
    assert not path.exists()


def test_background_monitor_marks_offline_once_and_recovery_is_recorded():
    db = SessionLocal()
    try:
        for model in (RemoteAction, DeviceHeartbeat, DeviceRiskSnapshot, PairingSession, ManagedDevice, Alert, SecurityEvent):
            db.execute(delete(model))
        db.commit()
    finally:
        db.close()
    clean_settings = replace(
        get_settings(),
        managed_device_heartbeat_interval_seconds=1,
        managed_device_offline_after_seconds=1,
    )
    with TestClient(create_app(clean_settings)) as client:
        code = client.post("/api/pairing/request", json={"device_id": "monitor-device"}).json()["pairing_code"]
        token = client.post(
            "/api/pairing/complete",
            json={"pairing_code": code, "device_id": "monitor-device", "device_name": "Monitor Device"},
        ).json()["device_token"]
        headers = {"X-Device-Id": "monitor-device", "X-Device-Token": token}
        assert client.post(
            "/api/managed-devices/monitor-device/heartbeat",
            headers=headers,
            json={"heartbeat_id": "monitor-active-heartbeat"},
        ).status_code == 200
        db = SessionLocal()
        try:
            device = db.query(ManagedDevice).filter_by(device_id="monitor-device").one()
            device.last_seen = datetime.now(timezone.utc) - timedelta(seconds=10)
            db.commit()
        finally:
            db.close()
        time.sleep(1.4)
        assert client.get("/api/managed-devices/monitor-device/status").json()["status"] == "OFFLINE"
        time.sleep(1.2)
        db = SessionLocal()
        try:
            offline_events = db.query(SecurityEvent).filter(
                SecurityEvent.event_type == "DEVICE_OFFLINE",
                SecurityEvent.event_metadata["managed_device_id"].as_string() == "monitor-device",
            ).count()
        finally:
            db.close()
        assert offline_events == 1
        assert client.post(
            "/api/managed-devices/monitor-device/heartbeat",
            headers=headers,
            json={"heartbeat_id": "monitor-recovery-heartbeat"},
        ).status_code == 200
        assert client.get("/api/managed-devices/monitor-device/status").json()["status"] == "ACTIVE"
