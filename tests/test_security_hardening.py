from fastapi.testclient import TestClient

from backend.core.config import Settings
from backend.core.security import reset_rate_limiter
from backend.main import create_app


def test_status_endpoint_is_public_and_reports_auth_state():
    app = create_app(Settings())
    client = TestClient(app)

    response = client.get("/api/status")

    assert response.status_code == 200
    assert response.json()["authenticated"] is False


def test_status_endpoint_accepts_bearer_header_for_auth_state():
    client = TestClient(create_app(Settings(auth_enabled=True, api_token="abc123")))

    response = client.get("/api/status", headers={"Authorization": "Bearer abc123"})

    assert response.status_code == 200
    assert response.json()["authenticated"] is True


def test_protected_routes_require_authentication():
    app_settings = Settings(auth_enabled=True, api_token="test-token")
    client = TestClient(create_app(app_settings))

    missing = client.get("/api/devices")
    invalid = client.get("/api/devices", headers={"Authorization": "Bearer wrong"})
    bearer = client.get("/api/devices", headers={"Authorization": "Bearer test-token"})
    legacy = client.get("/api/devices", headers={"x-api-key": "test-token"})

    assert missing.status_code == 401
    assert invalid.status_code == 401
    assert bearer.status_code == 200
    assert legacy.status_code == 200


def test_auth_failure_rate_limit_triggers_429():
    reset_rate_limiter()
    client = TestClient(create_app(Settings(auth_enabled=True, api_token="test-token")))

    responses = [
        client.get("/api/devices", headers={"Authorization": "Bearer wrong"})
        for _ in range(6)
    ]

    assert responses[-1].status_code == 429


def test_invalid_startup_configuration_fails_clearly():
    try:
        create_app(Settings(api_host="8.8.8.8"))
    except ValueError as exc:
        assert "private LAN address" in str(exc)
    else:
        raise AssertionError("public host binding should be rejected")
