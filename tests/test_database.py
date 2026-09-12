from sqlalchemy import delete

from backend.database.session import SessionLocal, init_db
from backend.models import Alert, APKScan, DetectionRule, Device, RiskSnapshot, SecurityEvent, WebScan


def test_initial_models_can_be_persisted():
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

        device = Device(
            ip_address="192.168.1.15",
            mac_address="AA:BB:CC:DD:EE:FF",
            hostname="lab-phone",
            vendor="Samsung",
            status="online",
            known=False,
            notes="Samsung M02 dashboard candidate",
        )
        event = SecurityEvent(
            event_type="new_device",
            severity="MEDIUM",
            source="network",
            message="New device detected on local lab network.",
            event_metadata={"ip": "192.168.1.15"},
        )
        alert = Alert(
            severity="MEDIUM",
            title="New device detected",
            description="An unknown device appeared on the local lab network.",
            source="detection",
        )
        apk_scan = APKScan(
            filename="sample.apk",
            hash="a" * 64,
            risk_score=10,
            risk_level="LOW",
            permissions=["android.permission.INTERNET"],
            findings=[],
        )
        web_scan = WebScan(
            target="http://127.0.0.1:8000",
            risk_score=25,
            findings=[{"finding": "Missing header", "severity": "LOW"}],
        )

        db.add_all([device, event, alert, apk_scan, web_scan])
        db.commit()

        assert device.id is not None
        assert event.id is not None
        assert alert.id is not None
        assert apk_scan.id is not None
        assert web_scan.id is not None
    finally:
        db.execute(delete(Alert))
        db.execute(delete(APKScan))
        db.execute(delete(WebScan))
        db.execute(delete(SecurityEvent))
        db.execute(delete(Device))
        db.execute(delete(RiskSnapshot))
        db.execute(delete(DetectionRule))
        db.commit()
        db.close()
