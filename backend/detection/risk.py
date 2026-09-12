from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.core.config import Settings, get_settings
from backend.models import (
    Alert,
    APKScan,
    Device,
    DeviceRiskSnapshot,
    ManagedDevice,
    RiskSnapshot,
    SecurityEvent,
    WebScan,
)


SEVERITY_POINTS = {"LOW": 4, "MEDIUM": 12, "HIGH": 24, "CRITICAL": 40}
SOURCE_CAPS = {"ALERT": 35, "APK": 30, "WEBSEC": 25, "NETWORK": 20, "EVENT": 20}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def risk_level(score: int) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def _age_multiplier(age: timedelta) -> float:
    minutes = age.total_seconds() / 60
    if minutes <= 180:
        return 1.0
    if minutes <= 24 * 60:
        return 0.75
    if minutes <= 7 * 24 * 60:
        return 0.45
    if minutes <= 30 * 24 * 60:
        return 0.2
    return 0.0


def _clamp(value: int, low: int = 0, high: int = 100) -> int:
    return max(low, min(high, value))


def _signal_age(value: datetime | None) -> timedelta:
    if value is None:
        return timedelta(0)
    now = utc_now()
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return now - value


def _compact_signature(score: int, contributors: list[dict], reasons: list[str]) -> str:
    payload = {
        "score": score,
        "contributors": [
            {
                "source": item["source"],
                "reason": item["reason"],
                "points": item["points"],
                "related_id": item.get("related_id"),
            }
            for item in contributors
        ],
        "reasons": reasons,
    }
    digest = hashlib.sha1(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return digest


def _snapshot_dict(snapshot: RiskSnapshot) -> dict:
    return {
        "id": snapshot.id,
        "timestamp": snapshot.timestamp.isoformat() if snapshot.timestamp else None,
        "score": snapshot.score,
        "level": snapshot.level,
        "trend": snapshot.trend,
        "change": snapshot.change,
        "contributors": snapshot.contributors or [],
        "reasons": snapshot.reasons or [],
    }


def _latest_snapshot(db: Session) -> RiskSnapshot | None:
    return db.scalar(select(RiskSnapshot).order_by(RiskSnapshot.timestamp.desc()))


def _active_alert_points(alert: Alert) -> int:
    base = max(SEVERITY_POINTS.get((alert.severity or "LOW").upper(), 0), int(alert.risk_points or 0))
    bonus = max((alert.repeat_count or 1) - 1, 0) * 2
    age = _signal_age(alert.last_seen or alert.timestamp)
    points = int(round((base + bonus) * _age_multiplier(age)))
    return _clamp(points, 0, SOURCE_CAPS["ALERT"])


def _apk_points(scan: APKScan) -> int:
    base = max(int(scan.risk_score or 0), 0)
    points = min((base // 3) + (5 if (scan.risk_level or "LOW").upper() in {"HIGH", "CRITICAL"} else 0), SOURCE_CAPS["APK"])
    return int(round(points * _age_multiplier(_signal_age(scan.scan_time))))


def _web_points(scan: WebScan) -> int:
    base = max(int(scan.risk_score or 0), 0)
    points = min((base // 4) + (4 if (scan.risk_level or "LOW").upper() in {"HIGH", "CRITICAL"} else 0), SOURCE_CAPS["WEBSEC"])
    return int(round(points * _age_multiplier(_signal_age(scan.scan_time))))


def _device_points(device: Device) -> int:
    points = 0
    if device.status == "online" and not device.known:
        points += 6
    if device.services:
        points += min(len(device.services) * 2, 8)
    if device.hostname and device.hostname.lower().startswith("android"):
        points += 1
    return _clamp(points, 0, SOURCE_CAPS["NETWORK"])


def _event_points(event_type: str, count: int) -> int:
    if count < 3:
        return 0
    base = 6 + max(0, count - 3) * 2
    if event_type == "AUTH_FAILURE":
        base += 3
    if event_type == "RATE_LIMITED":
        base += 2
    return _clamp(base, 0, SOURCE_CAPS["EVENT"])


def _append_contribution(
    contributors: list[dict],
    reasons: list[str],
    category_totals: dict[str, int],
    *,
    source: str,
    reason: str,
    points: int,
    related_id: int | None = None,
    category: str | None = None,
) -> None:
    if points <= 0:
        return
    category = category or source
    current_total = category_totals.get(category, 0)
    capped = max(0, min(points, SOURCE_CAPS.get(category, 20) - current_total))
    if capped <= 0:
        return
    category_totals[category] = current_total + capped
    contributors.append(
        {
            "source": source,
            "reason": reason,
            "points": capped,
            "related_id": related_id,
            "category": category,
        }
    )
    reasons.append(f"{source}: {reason} (+{capped})")


def _collect_current_risk(db: Session) -> tuple[int, str, list[dict], list[str]]:
    contributors: list[dict] = []
    reasons: list[str] = []
    category_totals: dict[str, int] = {}
    score = 0

    active_alerts = db.scalars(
        select(Alert).where(Alert.status == "active").order_by(Alert.last_seen.desc(), Alert.timestamp.desc())
    ).all()
    for alert in active_alerts:
        points = _active_alert_points(alert)
        before = len(contributors)
        _append_contribution(
            contributors,
            reasons,
            category_totals,
            source="ALERT",
            reason=f"{(alert.severity or 'LOW').upper()} alert: {alert.title}",
            points=points,
            related_id=alert.id,
            category="ALERT",
        )
        score += sum(item["points"] for item in contributors[before:])

    apk_scans = db.scalars(select(APKScan).order_by(APKScan.scan_time.desc())).all()
    seen_apk_hashes: set[str] = set()
    for scan in apk_scans:
        if scan.hash in seen_apk_hashes:
            continue
        seen_apk_hashes.add(scan.hash)
        points = _apk_points(scan)
        before = len(contributors)
        _append_contribution(
            contributors,
            reasons,
            category_totals,
            source="APK",
            reason=f"{scan.filename} risk contribution",
            points=points,
            related_id=scan.id,
            category="APK",
        )
        score += sum(item["points"] for item in contributors[before:])
        if len(seen_apk_hashes) >= 3:
            break

    web_scans = db.scalars(select(WebScan).order_by(WebScan.scan_time.desc())).all()
    seen_web_targets: set[str] = set()
    for scan in web_scans:
        if scan.target in seen_web_targets:
            continue
        seen_web_targets.add(scan.target)
        points = _web_points(scan)
        before = len(contributors)
        _append_contribution(
            contributors,
            reasons,
            category_totals,
            source="WEBSEC",
            reason=f"{scan.target} risk contribution",
            points=points,
            related_id=scan.id,
            category="WEBSEC",
        )
        score += sum(item["points"] for item in contributors[before:])
        if len(seen_web_targets) >= 3:
            break

    devices = db.scalars(select(Device).order_by(Device.last_seen.desc())).all()
    for device in devices[:5]:
        points = _device_points(device)
        if points:
            before = len(contributors)
            _append_contribution(
                contributors,
                reasons,
                category_totals,
                source="NETWORK",
                reason=f"Device {device.ip_address} ({'unknown' if not device.known else 'known'})",
                points=points,
                related_id=device.id,
                category="NETWORK",
            )
            score += sum(item["points"] for item in contributors[before:])

    auth_window = utc_now() - timedelta(minutes=30)
    recent_events = db.scalars(
        select(SecurityEvent).where(SecurityEvent.timestamp >= auth_window)
    ).all()
    repeated_counts: dict[str, int] = {}
    for event in recent_events:
        if (event.event_metadata or {}).get("managed_device_id"):
            continue
        repeated_counts[event.event_type] = repeated_counts.get(event.event_type, 0) + 1
    for event_type, count in repeated_counts.items():
        points = _event_points(event_type, int(count))
        if points:
            before = len(contributors)
            _append_contribution(
                contributors,
                reasons,
                category_totals,
                source="EVENT",
                reason=f"Repeated {event_type.lower()} events ({count} in 30 minutes)",
                points=points,
                category="EVENT",
            )
            score += sum(item["points"] for item in contributors[before:])

    score = _clamp(score, 0, 100)
    return score, risk_level(score), contributors[:10], reasons[:8] or ["No active risk contributors recorded."]


def _device_snapshot_dict(snapshot: DeviceRiskSnapshot) -> dict:
    return {
        "id": snapshot.id,
        "device_id": snapshot.device_id,
        "timestamp": snapshot.timestamp.isoformat() if snapshot.timestamp else None,
        "score": snapshot.score,
        "level": snapshot.level,
        "trend": snapshot.trend,
        "change": snapshot.change,
        "contributors": snapshot.contributors or [],
        "reasons": snapshot.reasons or [],
    }


def calculate_device_risk(db: Session, device_id: str, *, limit_events: int = 200) -> dict:
    """Calculate risk for one explicitly managed device without adding it to global risk twice."""
    device = db.scalar(select(ManagedDevice).where(ManagedDevice.device_id == device_id))
    if device is None:
        raise ValueError("Managed device not found.")
    contributors: list[dict] = []
    reasons: list[str] = []
    score = 0
    active_alerts = db.scalars(
        select(Alert).where(Alert.status == "active", Alert.managed_device_id == device_id)
        .order_by(Alert.last_seen.desc()).limit(50)
    ).all()
    for alert in active_alerts:
        points = max(SEVERITY_POINTS.get((alert.severity or "LOW").upper(), 0), int(alert.risk_points or 0))
        points = min(points, 35)
        if points:
            contributors.append({"source": "ALERT", "reason": alert.title, "points": points, "related_id": alert.id})
            reasons.append(f"Alert: {alert.title} (+{points})")
            score += points

    events = db.scalars(select(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).limit(limit_events)).all()
    matching = [event for event in events if (event.event_metadata or {}).get("managed_device_id") == device_id]
    recent_high = sum(1 for event in matching[:50] if (event.severity or "LOW").upper() in {"HIGH", "CRITICAL"})
    if recent_high:
        points = min(recent_high * 8, 30)
        contributors.append({"source": "DEVICE_EVENT", "reason": f"{recent_high} recent high-severity device events", "points": points})
        reasons.append(f"High-severity device events (+{points})")
        score += points
    if device.status == "OFFLINE":
        contributors.append({"source": "DEVICE_STATUS", "reason": "Device is unreachable", "points": 8})
        reasons.append("Device is unreachable (+8)")
        score += 8
    score = _clamp(score)
    level = risk_level(score)
    normalized_reasons = reasons[:8] or ["No active risk contributors recorded."]
    latest = db.scalar(
        select(DeviceRiskSnapshot).where(DeviceRiskSnapshot.device_id == device_id)
        .order_by(DeviceRiskSnapshot.timestamp.desc())
    )
    change = 0 if latest is None else score - latest.score
    trend = "STABLE" if change == 0 else "UP" if change > 0 else "DOWN"
    if latest is None or latest.score != score or latest.level != level or latest.contributors != contributors[:10] or latest.reasons != normalized_reasons:
        snapshot = DeviceRiskSnapshot(
            device_id=device_id,
            score=score,
            level=level,
            trend=trend,
            change=change,
            contributors=contributors[:10],
            reasons=normalized_reasons,
        )
        db.add(snapshot)
        db.commit()
        db.refresh(snapshot)
    else:
        snapshot = latest
    return {**_device_snapshot_dict(snapshot), "history": get_device_risk_history(db, device_id, limit=5)["items"]}


def get_device_risk_history(db: Session, device_id: str, *, limit: int = 20) -> dict:
    rows = db.scalars(
        select(DeviceRiskSnapshot).where(DeviceRiskSnapshot.device_id == device_id)
        .order_by(DeviceRiskSnapshot.timestamp.desc()).limit(limit)
    ).all()
    return {"items": [_device_snapshot_dict(row) for row in rows], "summary": {"total": len(rows), "limit": limit}}


def record_risk_snapshot(
    db: Session,
    *,
    score: int,
    level: str,
    contributors: list[dict],
    reasons: list[str],
) -> dict:
    latest = _latest_snapshot(db)
    signature = _compact_signature(score, contributors, reasons)
    existing_signature = db.scalar(
        select(RiskSnapshot).where(RiskSnapshot.signature == signature)
    )
    if existing_signature is not None:
        return _snapshot_dict(existing_signature)
    if latest and latest.signature == signature:
        return _snapshot_dict(latest)

    if latest is None:
        trend = "STABLE"
        change = 0
    else:
        change = score - latest.score
        trend = "UP" if change > 0 else "DOWN" if change < 0 else "STABLE"

    snapshot = RiskSnapshot(
        score=score,
        level=level,
        trend=trend,
        change=change,
        signature=signature,
        contributors=contributors,
        reasons=reasons,
    )
    db.add(snapshot)
    db.commit()
    db.refresh(snapshot)
    return _snapshot_dict(snapshot)


def calculate_lab_risk(db: Session, settings: Settings | None = None) -> dict:
    settings = settings or get_settings()
    score, level, contributors, reasons = _collect_current_risk(db)
    snapshot = record_risk_snapshot(
        db,
        score=score,
        level=level,
        contributors=contributors,
        reasons=reasons,
    )
    history = get_risk_history(db, limit=5)["items"]
    snapshot.update(
        {
            "label": "LAB RISK SCORE",
            "reasons": reasons,
            "contributors": contributors,
            "history": history,
            "thresholds": {
                "medium": 25,
                "high": 50,
                "critical": 75,
                "alert_high": settings.alert_high_threshold,
                "alert_critical": settings.alert_critical_threshold,
            },
        }
    )
    return snapshot


def get_risk_history(db: Session, *, limit: int = 20, offset: int = 0) -> dict:
    rows = db.scalars(
        select(RiskSnapshot)
        .order_by(RiskSnapshot.timestamp.desc())
        .offset(offset)
        .limit(limit)
    ).all()
    total = db.scalar(select(func.count(RiskSnapshot.id))) or 0
    return {
        "items": [_snapshot_dict(snapshot) for snapshot in rows],
        "summary": {
            "total": total,
            "limit": limit,
            "offset": offset,
        },
    }
