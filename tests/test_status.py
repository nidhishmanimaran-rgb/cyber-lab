from fastapi.testclient import TestClient
from sqlalchemy import delete

from backend.core.config import Settings, get_settings
from backend.core.security import reset_rate_limiter
from backend.database.session import SessionLocal, init_db
from backend.main import create_app
from backend.models import Alert, SecurityEvent


def clear_auth_records():
    reset_rate_limiter()
    init_db()
    db = SessionLocal()
    try:
        db.execute(delete(Alert).where(Alert.source == "auth"))
        db.execute(delete(SecurityEvent).where(SecurityEvent.source == "auth"))
        db.commit()
    finally:
        db.close()


def test_status_endpoint_returns_foundation_status():
    app = create_app()
    client = TestClient(app)

    response = client.get("/api/status")

    assert response.status_code == 200
    data = response.json()
    assert data["service"] == "Cyber Command Center"
    assert data["status"] == "ok"
    assert data["database"] == "ok"
    assert data["environment"] == "local-lab"
    assert set(data["counts"]) == {
        "devices",
        "events",
        "alerts",
        "apk_scans",
        "web_scans",
    }


def test_status_endpoint_is_public_when_auth_enabled():
    clear_auth_records()
    client = TestClient(create_app(Settings(
        auth_enabled=True,
        api_token="test-token",
    )))

    status_response = client.get("/api/status")
    protected_missing = client.get("/api/devices")
    protected_valid = client.get("/api/devices", headers={"Authorization": "Bearer test-token"})
    legacy_valid = client.get("/api/devices", headers={"x-api-key": "test-token"})

    assert status_response.status_code == 200
    assert status_response.json()["authenticated"] is False
    assert protected_missing.status_code == 401
    assert protected_valid.status_code == 200
    assert legacy_valid.status_code == 200
    clear_auth_records()
