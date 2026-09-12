from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.core.config import Settings, get_settings
from backend.models import Alert, DetectionRule, Device, SecurityEvent


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


RULE_DEFINITIONS: list[dict] = [
    {
        "rule_id": "NEW_DEVICE",
        "name": "New device detected",
        "description": "Creates a medium alert when a previously unseen LAN device appears.",
        "category": "network",
        "severity": "MEDIUM",
        "enabled": True,
        "risk_points": 10,
        "cooldown_seconds": 1800,
        "threshold": None,
        "version": "1.0",
        "metadata": {"window_minutes": 60},
    },
    {
        "rule_id": "REPEATED_SUSPICIOUS_EVENT",
        "name": "Repeated suspicious event",
        "description": "Escalates repeated suspicious security events in a short window.",
        "category": "correlation",
        "severity": "HIGH",
        "enabled": True,
        "risk_points": 15,
        "cooldown_seconds": 1800,
        "threshold": 3,
        "version": "1.0",
        "metadata": {"window_minutes": 30},
    },
    {
        "rule_id": "REPEATED_AUTH_FAILURES",
        "name": "Repeated authentication failures",
        "description": "Creates an alert when authentication failures repeat from the same source.",
        "category": "auth",
        "severity": "HIGH",
        "enabled": True,
        "risk_points": 14,
        "cooldown_seconds": 1800,
        "threshold": 5,
        "version": "1.0",
        "metadata": {"window_minutes": 30},
    },
    {
        "rule_id": "HIGH_RISK_APK",
        "name": "High-risk APK",
        "description": "Creates an alert when APK analysis reports a high risk level.",
        "category": "apk",
        "severity": "HIGH",
        "enabled": True,
        "risk_points": 25,
        "cooldown_seconds": 3600,
        "threshold": None,
        "version": "1.0",
        "metadata": {},
    },
    {
        "rule_id": "CRITICAL_APK",
        "name": "Critical APK",
        "description": "Creates a critical alert when APK analysis reports critical risk.",
        "category": "apk",
        "severity": "CRITICAL",
        "enabled": True,
        "risk_points": 25,
        "cooldown_seconds": 3600,
        "threshold": None,
        "version": "1.0",
        "metadata": {},
    },
    {
        "rule_id": "WEBSEC_HIGH_RISK",
        "name": "High-risk WebSec finding",
        "description": "Creates a high alert when WebSec reports a high-risk finding.",
        "category": "websec",
        "severity": "HIGH",
        "enabled": True,
        "risk_points": 12,
        "cooldown_seconds": 3600,
        "threshold": None,
        "version": "1.0",
        "metadata": {},
    },
    {
        "rule_id": "WEBSEC_CRITICAL",
        "name": "Critical WebSec finding",
        "description": "Creates a critical alert when WebSec reports a critical finding.",
        "category": "websec",
        "severity": "CRITICAL",
        "enabled": True,
        "risk_points": 20,
        "cooldown_seconds": 3600,
        "threshold": None,
        "version": "1.0",
        "metadata": {},
    },
    {
        "rule_id": "MULTIPLE_ACTIVE_ALERTS",
        "name": "Multiple active alerts",
        "description": "Escalates when too many active alerts are open at once.",
        "category": "correlation",
        "severity": "HIGH",
        "enabled": True,
        "risk_points": 10,
        "cooldown_seconds": 1800,
        "threshold": 3,
        "version": "1.0",
        "metadata": {"window_minutes": 120},
    },
    {
        "rule_id": "RISK_ESCALATION",
        "name": "Risk escalation",
        "description": "Records an escalation when the lab risk rises sharply.",
        "category": "risk",
        "severity": "HIGH",
        "enabled": True,
        "risk_points": 0,
        "cooldown_seconds": 900,
        "threshold": 12,
        "version": "1.0",
        "metadata": {"minimum_level": "MEDIUM"},
    },
    {
        "rule_id": "RISK_RECOVERY",
        "name": "Risk recovery",
        "description": "Records a recovery when the lab risk falls.",
        "category": "risk",
        "severity": "LOW",
        "enabled": True,
        "risk_points": 0,
        "cooldown_seconds": 900,
        "threshold": 8,
        "version": "1.0",
        "metadata": {"maximum_level": "MEDIUM"},
    },
    {
        "rule_id": "DEVICE_OFFLINE",
        "name": "Managed device offline",
        "description": "Records when an authorized managed device becomes unreachable.",
        "category": "managed_device",
        "severity": "MEDIUM",
        "enabled": True,
        "risk_points": 8,
        "cooldown_seconds": 1800,
        "threshold": None,
        "version": "1.0",
        "metadata": {},
    },
]


def seed_detection_rules(db: Session) -> None:
    existing = {row.rule_id for row in db.scalars(select(DetectionRule)).all()}
    created = False
    for definition in RULE_DEFINITIONS:
        if definition["rule_id"] in existing:
            continue
        db.add(
            DetectionRule(
                rule_id=definition["rule_id"],
                name=definition["name"],
                description=definition["description"],
                category=definition["category"],
                severity=definition["severity"],
                enabled=definition["enabled"],
                risk_points=definition["risk_points"],
                cooldown_seconds=definition["cooldown_seconds"],
                threshold=definition["threshold"],
                version=definition["version"],
                rule_metadata=definition["metadata"],
            )
        )
        created = True
    if created:
        db.commit()


def list_rules(db: Session) -> list[DetectionRule]:
    seed_detection_rules(db)
    return db.scalars(select(DetectionRule).order_by(DetectionRule.category, DetectionRule.rule_id)).all()


def get_rule(db: Session, rule_id: str) -> DetectionRule | None:
    seed_detection_rules(db)
    return db.scalar(select(DetectionRule).where(DetectionRule.rule_id == rule_id))


def _rule_hit(
    rule: DetectionRule,
    *,
    severity: str | None = None,
    title: str | None = None,
    description: str | None = None,
    source: str | None = None,
    risk_points: int | None = None,
    cooldown_seconds: int | None = None,
    related_event_id: int | None = None,
    metadata: dict | None = None,
    action: str = "alert",
) -> dict:
    return {
        "rule_id": rule.rule_id,
        "severity": (severity or rule.severity).upper(),
        "title": title or rule.name,
        "description": description or rule.description,
        "source": source or rule.category,
        "risk_points": rule.risk_points if risk_points is None else risk_points,
        "cooldown_seconds": cooldown_seconds if cooldown_seconds is not None else rule.cooldown_seconds,
        "related_event_id": related_event_id,
        "metadata": metadata or {},
        "action": action,
    }


def evaluate_event_rules(db: Session, event: SecurityEvent, settings: Settings | None = None) -> list[dict]:
    seed_detection_rules(db)
    settings = settings or get_settings()
    now = utc_now()
    metadata = event.event_metadata or {}
    event_type = event.event_type.upper()
    severity = event.severity.upper()
    hits: list[dict] = []

    rule = get_rule(db, "NEW_DEVICE")
    if rule and rule.enabled and event_type == "NEW_DEVICE":
        hits.append(
            _rule_hit(
                rule,
                severity="MEDIUM",
                title="New device detected",
                description=event.message,
                source="network",
                risk_points=rule.risk_points,
                cooldown_seconds=rule.cooldown_seconds,
                related_event_id=event.id,
                metadata={
                    "device_id": metadata.get("device_id"),
                    "ip_address": metadata.get("ip_address"),
                    "timestamp": now.isoformat(),
                },
            )
        )

    rule = get_rule(db, "REPEATED_SUSPICIOUS_EVENT")
    if rule and rule.enabled:
        window = now - timedelta(minutes=rule.rule_metadata.get("window_minutes", 30))
        suspicious_types = {"AUTH_FAILURE", "RATE_LIMITED", "DEVICE_OFFLINE", "DEVICE_ONLINE"}
        if event_type in suspicious_types:
            count = db.scalar(
                select(func.count(SecurityEvent.id)).where(
                    SecurityEvent.event_type == event_type,
                    SecurityEvent.source == event.source,
                    SecurityEvent.timestamp >= window,
                )
            ) or 0
            if count >= (rule.threshold or 3):
                hits.append(
                    _rule_hit(
                        rule,
                        severity=rule.severity,
                        title="Repeated suspicious activity",
                        description=f"{count} {event_type.lower()} events were observed in the last {rule.rule_metadata.get('window_minutes', 30)} minutes.",
                        source=event.source,
                        risk_points=min(rule.risk_points + (count - (rule.threshold or 3)) * 2, 20),
                        cooldown_seconds=rule.cooldown_seconds,
                        related_event_id=event.id,
                        metadata={"count": count, "window_minutes": rule.rule_metadata.get("window_minutes", 30)},
                    )
                )

    rule = get_rule(db, "REPEATED_AUTH_FAILURES")
    if rule and rule.enabled and event_type == "AUTH_FAILURE" and event.source == "auth":
        window = now - timedelta(minutes=rule.rule_metadata.get("window_minutes", 30))
        failure_count = db.scalar(
            select(func.count(SecurityEvent.id)).where(
                SecurityEvent.event_type == "AUTH_FAILURE",
                SecurityEvent.source == "auth",
                SecurityEvent.timestamp >= window,
            )
        ) or 0
        if failure_count >= (rule.threshold or 5):
            hits.append(
                _rule_hit(
                    rule,
                    severity=rule.severity,
                    title="Repeated authentication failures",
                    description=f"{failure_count} authentication failures were observed in the last {rule.rule_metadata.get('window_minutes', 30)} minutes.",
                    source="auth",
                    risk_points=min(rule.risk_points + (failure_count - (rule.threshold or 5)) * 2, 20),
                    cooldown_seconds=rule.cooldown_seconds,
                    related_event_id=event.id,
                    metadata={
                        "failure_count": failure_count,
                        "window_minutes": rule.rule_metadata.get("window_minutes", 30),
                    },
                )
            )

    rule = get_rule(db, "HIGH_RISK_APK")
    if rule and rule.enabled and event_type == "APK_SCAN_COMPLETED" and severity in {"HIGH", "CRITICAL"}:
        hits.append(
            _rule_hit(
                rule,
                severity="HIGH",
                title="High-risk APK scan",
                description=event.message,
                source="apk",
                risk_points=rule.risk_points,
                cooldown_seconds=rule.cooldown_seconds,
                related_event_id=event.id,
                metadata={"risk_score": metadata.get("risk_score")},
            )
        )

    rule = get_rule(db, "CRITICAL_APK")
    if rule and rule.enabled and event_type == "APK_SCAN_COMPLETED" and severity == "CRITICAL":
        hits.append(
            _rule_hit(
                rule,
                severity="CRITICAL",
                title="Critical APK scan",
                description=event.message,
                source="apk",
                risk_points=rule.risk_points,
                cooldown_seconds=rule.cooldown_seconds,
                related_event_id=event.id,
                metadata={"risk_score": metadata.get("risk_score")},
            )
        )

    rule = get_rule(db, "WEBSEC_HIGH_RISK")
    if rule and rule.enabled and event_type == "WEBSEC_SCAN_COMPLETED" and severity == "HIGH":
        hits.append(
            _rule_hit(
                rule,
                severity="HIGH",
                title="High-risk WebSec finding",
                description=event.message,
                source="websec",
                risk_points=rule.risk_points,
                cooldown_seconds=rule.cooldown_seconds,
                related_event_id=event.id,
                metadata={"highest_severity": metadata.get("highest_severity")},
            )
        )

    rule = get_rule(db, "WEBSEC_CRITICAL")
    if rule and rule.enabled and event_type == "WEBSEC_SCAN_COMPLETED" and severity == "CRITICAL":
        hits.append(
            _rule_hit(
                rule,
                severity="CRITICAL",
                title="Critical WebSec finding",
                description=event.message,
                source="websec",
                risk_points=rule.risk_points,
                cooldown_seconds=rule.cooldown_seconds,
                related_event_id=event.id,
                metadata={"highest_severity": metadata.get("highest_severity")},
            )
        )

    rule = get_rule(db, "DEVICE_OFFLINE")
    if rule and rule.enabled and event_type == "DEVICE_OFFLINE":
        hits.append(
            _rule_hit(
                rule,
                severity="MEDIUM",
                title="Managed device offline",
                description=event.message,
                source="managed_device",
                risk_points=rule.risk_points,
                cooldown_seconds=rule.cooldown_seconds,
                related_event_id=event.id,
                metadata={"managed_device_id": metadata.get("managed_device_id")},
            )
        )

    return hits


def evaluate_risk_rules(db: Session, risk: dict) -> list[dict]:
    seed_detection_rules(db)
    hits: list[dict] = []
    latest = db.scalar(select(SecurityEvent).order_by(SecurityEvent.timestamp.desc()))
    if latest is None:
        return hits

    current_score = int(risk.get("score", 0))
    change = int(risk.get("change", 0))
    level = str(risk.get("level", "LOW")).upper()

    rule = get_rule(db, "RISK_ESCALATION")
    if rule and rule.enabled and change >= (rule.threshold or 12) and level in {"MEDIUM", "HIGH", "CRITICAL"}:
        hits.append(
            _rule_hit(
                rule,
                severity=rule.severity,
                title="Risk escalation detected",
                description=f"Lab risk increased by {change} points to {current_score}.",
                source="risk",
                risk_points=0,
                cooldown_seconds=rule.cooldown_seconds,
                related_event_id=latest.id,
                metadata={"score": current_score, "change": change, "level": level},
                action="event",
            )
        )

    rule = get_rule(db, "RISK_RECOVERY")
    if rule and rule.enabled and change < 0 and current_score <= 24:
        hits.append(
            _rule_hit(
                rule,
                severity="LOW",
                title="Risk recovery detected",
                description=f"Lab risk fell by {abs(change)} points to {current_score}.",
                source="risk",
                risk_points=0,
                cooldown_seconds=rule.cooldown_seconds,
                related_event_id=latest.id,
                metadata={"score": current_score, "change": change, "level": level},
                action="event",
            )
        )

    rule = get_rule(db, "MULTIPLE_ACTIVE_ALERTS")
    if rule and rule.enabled:
        active_alerts = db.scalar(select(func.count(Alert.id)).where(Alert.status == "active")) or 0
        if active_alerts >= (rule.threshold or 3):
            hits.append(
                _rule_hit(
                    rule,
                    severity="HIGH",
                    title="Multiple active alerts",
                    description=f"{active_alerts} active alerts are open at once.",
                    source="alerts",
                    risk_points=rule.risk_points,
                    cooldown_seconds=rule.cooldown_seconds,
                    related_event_id=latest.id,
                    metadata={"active_alerts": active_alerts, "score": current_score},
                )
            )

    return hits
