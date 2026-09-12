from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.core.config import Settings, get_settings
from backend.core.logging import get_logger
from backend.detection.risk import calculate_lab_risk
from backend.detection.rules import evaluate_event_rules, evaluate_risk_rules
from backend.models import Alert, SecurityEvent


logger = get_logger("backend.detection")
SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_severity(value: str | None) -> str:
    return (value or "LOW").upper()


def _severity_rank(value: str | None) -> int:
    return SEVERITY_ORDER.get(_normalize_severity(value), 0)


def _merge_rule_metadata(existing: dict | None, new: dict | None) -> dict:
    merged = dict(existing or {})
    for key, value in (new or {}).items():
        if value is not None:
            merged[key] = value
    return merged


def _persist_security_event(
    db: Session,
    *,
    event_type: str,
    severity: str,
    source: str,
    message: str,
    metadata: dict | None = None,
) -> SecurityEvent:
    event = SecurityEvent(
        event_type=event_type.upper(),
        severity=_normalize_severity(severity),
        source=source,
        message=message,
        event_metadata=metadata or {},
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    logger.info(
        "security_event_recorded",
        extra={
            "ccc_module": "detection",
            "metadata": {
                "event_type": event.event_type,
                "severity": event.severity,
                "source": event.source,
            },
        },
    )
    return event


def upsert_alert(
    db: Session,
    *,
    severity: str,
    title: str,
    description: str,
    source: str,
    related_event_id: int | None = None,
    rule_id: str | None = None,
    rule_metadata: dict | None = None,
    risk_points: int = 0,
    cooldown_seconds: int = 900,
    managed_device_id: str | None = None,
) -> Alert:
    now = utc_now()
    severity = _normalize_severity(severity)
    query = select(Alert).where(
        Alert.title == title,
        Alert.source == source,
        Alert.status == "active",
    )
    if rule_id is not None:
        query = query.where(Alert.rule_id == rule_id)
    if managed_device_id is not None:
        query = query.where(Alert.managed_device_id == managed_device_id)
    existing = db.scalar(query.order_by(Alert.last_seen.desc(), Alert.timestamp.desc()))
    if existing is not None:
        existing.repeat_count = (existing.repeat_count or 1) + 1
        existing.last_seen = now
        existing.cooldown_until = now + timedelta(seconds=max(cooldown_seconds, 60))
        existing.risk_points = max(existing.risk_points or 0, risk_points)
        if _severity_rank(severity) > _severity_rank(existing.severity):
            existing.severity = severity
        existing.description = description or existing.description
        existing.rule_metadata = _merge_rule_metadata(existing.rule_metadata, rule_metadata)
        if related_event_id is not None:
            existing.related_event_id = related_event_id
        if managed_device_id is not None:
            existing.managed_device_id = managed_device_id
        db.commit()
        db.refresh(existing)
        logger.info(
            "alert_deduplicated",
            extra={
                "ccc_module": "alerts",
                "metadata": {
                    "alert_id": existing.id,
                    "rule_id": existing.rule_id,
                    "repeat_count": existing.repeat_count,
                    "source": existing.source,
                },
            },
        )
        return existing

    alert = Alert(
        severity=severity,
        title=title,
        description=description,
        source=source,
        status="active",
        last_seen=now,
        repeat_count=1,
        risk_points=risk_points,
        cooldown_until=now + timedelta(seconds=max(cooldown_seconds, 60)),
        related_event_id=related_event_id,
        rule_id=rule_id,
        rule_metadata=rule_metadata or {},
        managed_device_id=managed_device_id,
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    logger.info(
        "alert_generated",
        extra={
            "ccc_module": "alerts",
            "metadata": {
                "alert_id": alert.id,
                "rule_id": rule_id,
                "title": title,
                "source": source,
            },
        },
    )
    return alert


def create_alert_once(
    db: Session,
    *,
    severity: str,
    title: str,
    description: str,
    source: str,
    related_event_id: int | None = None,
    rule_id: str | None = None,
    rule_metadata: dict | None = None,
    risk_points: int = 0,
    cooldown_seconds: int = 900,
    managed_device_id: str | None = None,
) -> Alert | None:
    return upsert_alert(
        db,
        severity=severity,
        title=title,
        description=description,
        source=source,
        related_event_id=related_event_id,
        rule_id=rule_id,
        rule_metadata=rule_metadata,
        risk_points=risk_points,
        cooldown_seconds=cooldown_seconds,
        managed_device_id=managed_device_id,
    )


def create_event(
    db: Session,
    *,
    event_type: str,
    severity: str,
    source: str,
    message: str,
    metadata: dict | None = None,
    process_rules: bool = True,
    trigger_automation: bool = True,
    settings: Settings | None = None,
) -> SecurityEvent:
    event = _persist_security_event(
        db,
        event_type=event_type,
        severity=severity,
        source=source,
        message=message,
        metadata=metadata,
    )

    if not process_rules:
        return event

    settings = settings or get_settings()
    try:
        event_hits = evaluate_event_rules(db, event, settings)
        for hit in event_hits:
            if hit["action"] == "alert":
                upsert_alert(
                    db,
                    severity=hit["severity"],
                    title=hit["title"],
                    description=hit["description"],
                    source=hit["source"],
                    related_event_id=hit.get("related_event_id"),
                    rule_id=hit["rule_id"],
                    rule_metadata=hit.get("metadata"),
                    risk_points=hit.get("risk_points", 0),
                    cooldown_seconds=hit.get("cooldown_seconds", 900),
                    managed_device_id=(event.event_metadata or {}).get("managed_device_id"),
                )

        risk = calculate_lab_risk(db, settings=settings)
        if trigger_automation:
            automation_hits = evaluate_risk_rules(db, risk)
            for hit in automation_hits:
                if hit["action"] == "alert":
                    upsert_alert(
                        db,
                        severity=hit["severity"],
                        title=hit["title"],
                        description=hit["description"],
                        source=hit["source"],
                        related_event_id=hit.get("related_event_id"),
                        rule_id=hit["rule_id"],
                        rule_metadata=hit.get("metadata"),
                        risk_points=hit.get("risk_points", 0),
                        cooldown_seconds=hit.get("cooldown_seconds", 900),
                        managed_device_id=(event.event_metadata or {}).get("managed_device_id"),
                    )
                else:
                    _persist_security_event(
                        db,
                        event_type=hit["rule_id"],
                        severity=hit["severity"],
                        source=hit["source"],
                        message=hit["description"],
                        metadata={
                            **hit.get("metadata", {}),
                            "rule_id": hit["rule_id"],
                            "risk_score": risk.get("score"),
                            "risk_level": risk.get("level"),
                        },
                    )
            if automation_hits:
                calculate_lab_risk(db, settings=settings)
    except Exception:
        db.rollback()
        logger.exception(
            "detection_rule_failure",
            extra={
                "ccc_module": "detection",
                "metadata": {"event_type": event.event_type, "source": event.source},
            },
        )
    return event


def acknowledge_alert_record(db: Session, alert: Alert) -> Alert:
    now = utc_now()
    alert.status = "acknowledged"
    alert.acknowledged_at = now
    alert.last_seen = now
    db.commit()
    db.refresh(alert)
    _persist_security_event(
        db,
        event_type="ALERT_ACKNOWLEDGED",
        severity=alert.severity,
        source=alert.source,
        message=f"Alert acknowledged: {alert.title}",
        metadata={"alert_id": alert.id, "rule_id": alert.rule_id},
    )
    logger.info(
        "alert_acknowledged",
        extra={
            "ccc_module": "alerts",
            "metadata": {"alert_id": alert.id, "rule_id": alert.rule_id},
        },
    )
    calculate_lab_risk(db)
    return alert


def resolve_alert_record(db: Session, alert: Alert) -> Alert:
    now = utc_now()
    alert.status = "resolved"
    alert.resolved_at = now
    alert.last_seen = now
    db.commit()
    db.refresh(alert)
    _persist_security_event(
        db,
        event_type="ALERT_RESOLVED",
        severity=alert.severity,
        source=alert.source,
        message=f"Alert resolved: {alert.title}",
        metadata={"alert_id": alert.id, "rule_id": alert.rule_id},
    )
    logger.info(
        "alert_resolved",
        extra={
            "ccc_module": "alerts",
            "metadata": {"alert_id": alert.id, "rule_id": alert.rule_id},
        },
    )
    calculate_lab_risk(db)
    return alert
