from __future__ import annotations

import threading
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO

from fastapi.testclient import TestClient
from sqlalchemy import delete, select

from backend.apk.analyzer import analyze_apk
from backend.core.config import Settings
from backend.crypto.hashlab import generate_verifier, verify_password
from backend.database.session import SessionLocal, init_db
from backend.detection.engine import create_event
from backend.main import create_app
from backend.models import Alert, APKScan, DetectionRule, Device, RiskSnapshot, SecurityEvent, WebScan
from backend.network.monitor import record_scan, validate_network_scope
from backend.websec.scanner import scan_target


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


def make_apk() -> bytes:
    manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.lab" android:versionName="1.0" android:versionCode="1">
  <uses-sdk android:minSdkVersion="23" android:targetSdkVersion="25" />
  <uses-permission android:name="android.permission.CAMERA" />
  <application android:debuggable="true" android:allowBackup="true" android:usesCleartextTraffic="true">
    <activity android:name=".MainActivity" android:exported="true" />
  </application>
</manifest>"""
    output = BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("AndroidManifest.xml", manifest)
        archive.writestr("META-INF/CERT.RSA", b"demo")
    return output.getvalue()


def test_network_scope_rejects_public_targets():
    settings = Settings()

    validate_network_scope("192.168.1.0/24", settings)

    try:
        validate_network_scope("8.8.8.0/24", settings)
    except ValueError as exc:
        assert "private" in str(exc)
    else:
        raise AssertionError("public network scope should be rejected")


def test_network_record_scan_creates_new_device_event_once():
    clear_database()
    db = SessionLocal()
    try:
        discovered = [{"ip_address": "192.168.1.15", "mac_address": "AA:BB:CC:DD:EE:FF", "hostname": None, "vendor": "Unknown", "status": "online"}]
        first = record_scan(db, discovered)
        second = record_scan(db, discovered)
        events = db.scalars(select(SecurityEvent).where(SecurityEvent.event_type == "NEW_DEVICE")).all()

        assert first["created"] == 1
        assert second["created"] == 0
        assert len(events) == 1
    finally:
        db.close()
        clear_database()


def test_apk_static_analysis_extracts_manifest_and_risk():
    result = analyze_apk(make_apk(), "sample.apk")

    assert result["sha256"]
    assert result["package_name"] == "com.example.lab"
    assert "android.permission.CAMERA" in result["permissions"]
    assert result["risk_level"] in {"HIGH", "CRITICAL"}
    assert any(item["title"] == "Debuggable application" for item in result["findings"])


def test_apk_api_rejects_malformed_upload():
    client = TestClient(create_app())

    response = client.post("/api/apk/scan", content=b"not an apk", headers={"x-filename": "bad.apk"})

    assert response.status_code == 400


def test_apk_api_rejects_oversized_upload_by_header():
    client = TestClient(create_app())

    response = client.post(
        "/api/apk/scan",
        content=b"",
        headers={"x-filename": "huge.apk", "content-length": str(61 * 1024 * 1024)},
    )

    assert response.status_code == 413


class LabHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Set-Cookie", "session=demo")
        self.end_headers()
        self.wfile.write(b"<html><body>local lab</body></html>")

    def log_message(self, format, *args):
        return


def test_websec_scanner_finds_local_lab_issues():
    server = ThreadingHTTPServer(("127.0.0.1", 0), LabHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        target = f"http://127.0.0.1:{server.server_port}/"
        result = scan_target(target, Settings(authorized_scan_targets=(target,)))
    finally:
        server.shutdown()

    assert result["findings"]
    assert result["risk_score"] > 0


def test_websec_rejects_public_target():
    try:
        scan_target("https://example.com/", Settings(authorized_scan_targets=()))
    except ValueError as exc:
        assert "authorized" in str(exc)
    else:
        raise AssertionError("public WebSec target should be rejected")


def test_websec_rejects_urls_with_credentials():
    try:
        scan_target("http://user:pass@127.0.0.1:8000/", Settings())
    except ValueError as exc:
        assert "credentials" in str(exc)
    else:
        raise AssertionError("credential-bearing WebSec URL should be rejected")


def test_hashlab_generates_salt_and_verifies_without_plaintext():
    first = generate_verifier("Correct Horse Battery 42!")
    second = generate_verifier("Correct Horse Battery 42!")

    assert first["salt"] != second["salt"]
    assert verify_password("Correct Horse Battery 42!", first["verifier"])["valid"]
    assert not verify_password("wrong", first["verifier"])["valid"]
    assert "Correct Horse" not in first["verifier"]


def test_detection_and_risk_alert_on_high_risk_apk_event():
    clear_database()
    db = SessionLocal()
    try:
        create_event(
            db,
            event_type="APK_SCAN_COMPLETED",
            severity="HIGH",
            source="apk",
            message="High-risk APK scan completed.",
            metadata={"risk_score": 80},
        )
        client = TestClient(create_app())
        risk = client.get("/api/risk").json()
        alerts = db.scalars(select(Alert).where(Alert.title == "High-risk APK scan")).all()

        assert alerts
        assert risk["score"] >= 25
        assert risk["level"] in {"MEDIUM", "HIGH", "CRITICAL"}
    finally:
        db.close()
        clear_database()


def test_repeated_auth_failures_create_rule_metadata_alert():
    clear_database()
    db = SessionLocal()
    try:
        for _ in range(5):
            create_event(
                db,
                event_type="AUTH_FAILURE",
                severity="MEDIUM",
                source="auth",
                message="Invalid or missing API key.",
                metadata={"path": "/api/status"},
            )
        alert = db.scalar(select(Alert).where(Alert.rule_id == "REPEATED_AUTH_FAILURES"))
        assert alert is not None
        assert alert.rule_metadata["failure_count"] >= 5
    finally:
        db.close()
        clear_database()


def test_device_services_are_returned_by_api():
    clear_database()
    db = SessionLocal()
    try:
        db.add(
            Device(
                ip_address="192.168.1.20",
                status="online",
                known=True,
                services=[{"port": 8001, "name": "ccc-api"}],
            )
        )
        db.commit()
        client = TestClient(create_app())
        data = client.get("/api/devices").json()
        assert data["items"][0]["services"] == [{"port": 8001, "name": "ccc-api"}]
    finally:
        db.close()
        clear_database()


def test_device_known_state_can_be_updated():
    clear_database()
    db = SessionLocal()
    try:
        device = Device(ip_address="192.168.1.21", status="online", known=False)
        db.add(device)
        db.commit()
        device_id = device.id
        client = TestClient(create_app())

        response = client.patch(f"/api/devices/{device_id}/known", json={"known": True})

        assert response.status_code == 200
        assert response.json()["known"] is True
    finally:
        db.close()
        clear_database()


def test_cors_uses_configured_allowed_origin():
    client = TestClient(create_app())

    response = client.options(
        "/api/status",
        headers={
            "origin": "http://127.0.0.1:8001",
            "access-control-request-method": "GET",
        },
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://127.0.0.1:8001"
