from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.models import Alert, RiskSnapshot, SecurityEvent


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _normalize(value: str | None) -> str:
    return (value or "").upper()


def _timeline_item(
    *,
    item_id: int,
    timestamp: datetime | None,
    item_type: str,
    source: str,
    severity: str | None,
    title: str,
    description: str,
    related_id: int | None = None,
    extra: dict | None = None,
) -> dict:
    payload = {
        "id": item_id,
        "timestamp": _iso(timestamp),
        "type": item_type,
        "source": source,
        "severity": _normalize(severity) if severity else None,
        "title": title,
        "description": description,
        "related_id": related_id,
    }
    if extra:
        payload["metadata"] = extra
    return payload


def build_timeline(db: Session, *, max_items: int = 500) -> list[dict]:
    items: list[dict] = []

    events = db.scalars(select(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).limit(max_items)).all()
    for event in events:
        items.append(
            _timeline_item(
                item_id=event.id,
                timestamp=event.timestamp,
                item_type=event.event_type.upper(),
                source=event.source,
                severity=event.severity,
                title=event.event_type.replace("_", " ").title(),
                description=event.message,
                related_id=event.id,
                extra=event.event_metadata or {},
            )
        )

    alerts = db.scalars(select(Alert).order_by(Alert.timestamp.desc()).limit(max_items)).all()
    for alert in alerts:
        items.append(
            _timeline_item(
                item_id=alert.id,
                timestamp=alert.timestamp,
                item_type="ALERT_CREATED",
                source=alert.source,
                severity=alert.severity,
                title=alert.title,
                description=alert.description,
                related_id=alert.id,
                extra={
                    "repeat_count": alert.repeat_count,
                    "risk_points": alert.risk_points,
                    "status": alert.status,
                    "managed_device_id": alert.managed_device_id,
                },
            )
        )
        if alert.acknowledged_at:
            items.append(
                _timeline_item(
                    item_id=alert.id,
                    timestamp=alert.acknowledged_at,
                    item_type="ALERT_ACKNOWLEDGED",
                    source=alert.source,
                    severity=alert.severity,
                    title=f"Alert acknowledged: {alert.title}",
                    description=alert.description,
                    related_id=alert.id,
                    extra={"status": "acknowledged"},
                )
            )
        if alert.resolved_at:
            items.append(
                _timeline_item(
                    item_id=alert.id,
                    timestamp=alert.resolved_at,
                    item_type="ALERT_RESOLVED",
                    source=alert.source,
                    severity=alert.severity,
                    title=f"Alert resolved: {alert.title}",
                    description=alert.description,
                    related_id=alert.id,
                    extra={"status": "resolved"},
                )
            )

    snapshots = db.scalars(select(RiskSnapshot).order_by(RiskSnapshot.timestamp.desc()).limit(max_items)).all()
    for snapshot in snapshots:
        items.append(
            _timeline_item(
                item_id=snapshot.id,
                timestamp=snapshot.timestamp,
                item_type="RISK_SNAPSHOT",
                source="risk",
                severity=snapshot.level,
                title=f"Lab risk {snapshot.level} ({snapshot.score})",
                description=f"Trend {snapshot.trend} by {snapshot.change} points.",
                related_id=snapshot.id,
                extra={
                    "score": snapshot.score,
                    "trend": snapshot.trend,
                    "change": snapshot.change,
                },
            )
        )

    items.sort(key=lambda item: item.get("timestamp") or "", reverse=True)
    return items


def filter_timeline(
    items: list[dict],
    *,
    item_type: str | None = None,
    source: str | None = None,
    severity: str | None = None,
    device_id: str | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
) -> list[dict]:
    def parse_timestamp(value: str | None) -> datetime | None:
        if not value:
            return None
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)

    filtered: list[dict] = []
    for item in items:
        timestamp = parse_timestamp(item.get("timestamp"))
        if item_type and item.get("type") != item_type:
            continue
        if source and _normalize(item.get("source")) != _normalize(source):
            continue
        if severity and _normalize(item.get("severity")) != _normalize(severity):
            continue
        if device_id and (item.get("metadata") or {}).get("managed_device_id") != device_id:
            continue
        if start and timestamp and timestamp < start:
            continue
        if end and timestamp and timestamp > end:
            continue
        filtered.append(item)
    return filtered
