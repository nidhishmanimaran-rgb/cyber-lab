from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlalchemy import delete

from backend.database.session import SessionLocal, init_db
from backend.main import create_app
from backend.models import Alert, APKScan, DetectionRule, Device, RiskSnapshot, SecurityEvent, WebScan


def clear_database():
    init_db()
    db = SessionLocal()
    try:
        db.execute(delete(Alert))
        db.execute(delete(APKScan))
        db.execute(delete(WebScan))
        db.execute(delete(SecurityEvent))
        db.execute(delete(Device))
        db.execute(delete(RiskSnapshot))
        db.execute(delete(DetectionRule))
        db.commit()
    finally:
        db.close()


def test_stats_returns_empty_dashboard_state():
    clear_database()
    client = TestClient(create_app())

    response = client.get("/api/stats")

    assert response.status_code == 200
    data = response.json()
    assert data == {
        "network_devices": 0,
        "apks_scanned": 0,
        "web_findings": 0,
        "security_events": 0,
        "active_alerts": 0,
        "overall_lab_risk": "LOW",
        "lab_risk_score": 0,
        "risk_reasons": ["No active risk contributors recorded."],
        "recent_activity": [],
    }


def test_events_are_newest_first_and_filterable():
    clear_database()
    db = SessionLocal()
    now = datetime.now(timezone.utc)
    try:
        older = SecurityEvent(
            timestamp=now - timedelta(minutes=5),
            event_type="device_seen",
            severity="LOW",
            source="network",
            message="Known device is online.",
        )
        newer = SecurityEvent(
            timestamp=now,
            event_type="alert_created",
            severity="HIGH",
            source="detection",
            message="High severity alert created.",
        )
        db.add_all([older, newer])
        db.commit()
    finally:
        db.close()

    client = TestClient(create_app())
    all_events = client.get("/api/events").json()["items"]
    filtered = client.get("/api/events", params={"severity": "HIGH"}).json()["items"]

    assert [item["event_type"] for item in all_events] == [
        "alert_created",
        "device_seen",
    ]
    assert len(filtered) == 1
    assert filtered[0]["source"] == "detection"


def test_alerts_can_be_acknowledged():
    clear_database()
    db = SessionLocal()
    try:
        alert = Alert(
            severity="CRITICAL",
            title="Critical lab alert",
            description="A critical condition was detected.",
            source="detection",
            status="active",
        )
        db.add(alert)
        db.commit()
        alert_id = alert.id
    finally:
        db.close()

    client = TestClient(create_app())
    response = client.patch(f"/api/alerts/{alert_id}/acknowledge")

    assert response.status_code == 200
    assert response.json()["status"] == "acknowledged"
    assert client.get("/api/stats").json()["active_alerts"] == 0


def test_alerts_can_be_resolved():
    clear_database()
    db = SessionLocal()
    try:
        alert = Alert(
            severity="HIGH",
            title="High lab alert",
            description="A high condition was detected.",
            source="detection",
            status="acknowledged",
        )
        db.add(alert)
        db.commit()
        alert_id = alert.id
    finally:
        db.close()

    client = TestClient(create_app())
    response = client.post(f"/api/alerts/{alert_id}/resolve")

    assert response.status_code == 200
    assert response.json()["status"] == "resolved"


def test_risk_history_and_timeline_endpoints_return_empty_state():
    clear_database()
    client = TestClient(create_app())

    risk_history = client.get("/api/risk/history")
    timeline = client.get("/api/timeline")
    rules = client.get("/api/rules")

    assert risk_history.status_code == 200
    assert risk_history.json()["items"] == []
    assert timeline.status_code == 200
    assert timeline.json()["items"] == []
    assert rules.status_code == 200
    assert any(rule["rule_id"] == "REPEATED_AUTH_FAILURES" for rule in rules.json()["items"])


def test_settings_do_not_expose_api_token_or_database_url():
    client = TestClient(create_app())

    response = client.get("/api/settings")

    assert response.status_code == 200
    data = response.json()
    assert "api_token" not in data
    assert "database_url" not in data
    assert data["database_type"] == "sqlite"
