from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from backend.apk.analyzer import analyze_apk
from backend.core.config import Settings, get_settings
from backend.core.logging import get_logger
from backend.core.security import rate_limiter, require_api_key
from backend.crypto.hashlab import generate_verifier, verify_password
from backend.database.session import get_db
from backend.detection.engine import acknowledge_alert_record, create_event, resolve_alert_record
from backend.detection.risk import calculate_device_risk, calculate_lab_risk, get_device_risk_history, get_risk_history
from backend.detection.rules import get_rule, list_rules
from backend.detection.timeline import build_timeline, filter_timeline
from backend.core.security import request_is_authenticated
from backend.models import (
    Alert,
    APKScan,
    DetectionRule,
    Device,
    DeviceHeartbeat,
    ManagedDevice,
    RemoteAction,
    SecurityEvent,
    WebScan,
)
from backend.managed.service import (
    authenticate_device,
    complete_pairing,
    create_pairing_session,
    device_from_request,
    mark_offline_devices,
    record_heartbeat,
)
from backend.managed.service import _secret_hash
import secrets
import uuid
from urllib.parse import urlparse
from backend.network.monitor import detect_local_networks, discover_devices, record_scan
from backend.websec.scanner import scan_target

router = APIRouter(prefix="/api", dependencies=[Depends(require_api_key)])
agent_router = APIRouter(prefix="/api")
logger = get_logger("backend.api")

ALLOWED_REMOTE_ACTIONS = {
    "REQUEST_HEARTBEAT",
    "REQUEST_SYSTEM_INFO",
    "REQUEST_NETWORK_STATUS",
    "REQUEST_SECURITY_STATUS",
    "TRIGGER_LOCAL_SECURITY_SCAN",
    "REFRESH_TELEMETRY",
}


class NetworkScanRequest(BaseModel):
    cidr: str | None = None


class DeviceKnownRequest(BaseModel):
    known: bool


class WebSecScanRequest(BaseModel):
    target: str


class HashRequest(BaseModel):
    password: str


class VerifyHashRequest(BaseModel):
    password: str
    verifier: str


class PairingRequest(BaseModel):
    device_name: str | None = Field(default=None, max_length=120)
    device_id: str | None = Field(default=None, max_length=64, pattern=r"^[A-Za-z0-9._:-]+$")


class PairingCompleteRequest(BaseModel):
    pairing_code: str = Field(min_length=16, max_length=80)
    device_id: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9._:-]+$")
    device_name: str = Field(min_length=1, max_length=120)
    device_type: str = Field(default="computer", max_length=40)
    platform: str = Field(default="windows", max_length=40)
    agent_version: str = Field(default="unknown", max_length=40)
    os_info: dict = Field(default_factory=dict)
    public_key_fingerprint: str | None = Field(default=None, max_length=128)


class HeartbeatRequest(BaseModel):
    heartbeat_id: str = Field(min_length=8, max_length=80)
    system_info: dict = Field(default_factory=dict)
    network_info: dict = Field(default_factory=dict)
    health: dict = Field(default_factory=dict)


class TelemetryRequest(BaseModel):
    telemetry_id: str = Field(min_length=8, max_length=80)
    event_type: str = Field(min_length=3, max_length=80, pattern=r"^[A-Za-z0-9_:-]+$")
    severity: str = Field(default="LOW", max_length=16)
    message: str = Field(min_length=1, max_length=1000)
    metadata: dict = Field(default_factory=dict)


class RemoteActionRequest(BaseModel):
    action_type: str = Field(min_length=3, max_length=64)
    requested_by: str = Field(default="api", max_length=120)


class RemoteActionResultRequest(BaseModel):
    status: str = Field(min_length=1, max_length=32)
    result_summary: str = Field(default="", max_length=1000)


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _event_status(event: SecurityEvent) -> str:
    return "acknowledged" if event.acknowledged else "new"


def _alert_payload(alert: Alert) -> dict:
    return {
        "id": alert.id,
        "timestamp": _iso(alert.timestamp),
        "last_seen": _iso(alert.last_seen),
        "severity": alert.severity.upper(),
        "title": alert.title,
        "description": alert.description,
        "source": alert.source,
        "status": alert.status,
        "repeat_count": alert.repeat_count,
        "risk_points": alert.risk_points,
        "cooldown_until": _iso(alert.cooldown_until),
        "acknowledged_at": _iso(alert.acknowledged_at),
        "resolved_at": _iso(alert.resolved_at),
        "related_event_id": alert.related_event_id,
        "rule_id": alert.rule_id,
        "rule_metadata": alert.rule_metadata or {},
        "managed_device_id": alert.managed_device_id,
    }


def _event_payload(event: SecurityEvent) -> dict:
    return {
        "id": event.id,
        "timestamp": _iso(event.timestamp),
        "severity": event.severity.upper(),
        "source": event.source,
        "event_type": event.event_type,
        "message": event.message,
        "status": _event_status(event),
        "metadata": event.event_metadata or {},
    }


def _rule_payload(rule: DetectionRule) -> dict:
    return {
        "id": rule.id,
        "rule_id": rule.rule_id,
        "name": rule.name,
        "description": rule.description,
        "category": rule.category,
        "severity": rule.severity,
        "enabled": rule.enabled,
        "risk_points": rule.risk_points,
        "cooldown_seconds": rule.cooldown_seconds,
        "threshold": rule.threshold,
        "version": rule.version,
        "metadata": rule.rule_metadata or {},
        "created_at": _iso(rule.created_at),
        "updated_at": _iso(rule.updated_at),
    }


def _device_payload(device: Device) -> dict:
    return {
        "id": device.id,
        "ip_address": device.ip_address,
        "mac_address": device.mac_address,
        "hostname": device.hostname,
        "vendor": device.vendor,
        "first_seen": _iso(device.first_seen),
        "last_seen": _iso(device.last_seen),
        "status": device.status,
        "known": device.known,
        "services": device.services or [],
        "notes": device.notes,
    }


def _managed_device_payload(device: ManagedDevice, *, risk: dict | None = None, alert_count: int = 0) -> dict:
    return {
        "id": device.id,
        "device_id": device.device_id,
        "device_name": device.device_name,
        "device_type": device.device_type,
        "platform": device.platform,
        "os_info": device.os_info or {},
        "agent_version": device.agent_version,
        "public_key_fingerprint": device.public_key_fingerprint,
        "created_at": _iso(device.created_at),
        "last_seen": _iso(device.last_seen),
        "status": device.status,
        "pairing_status": device.pairing_status,
        "revoked": device.revoked_at is not None or device.status == "REVOKED",
        "revoked_at": _iso(device.revoked_at),
        "network_info": device.network_info or {},
        "system_info": device.system_info or {},
        "risk": risk or {"score": 0, "level": "LOW", "trend": "STABLE", "change": 0},
        "active_alerts": alert_count,
    }


def _remote_action_payload(action: RemoteAction) -> dict:
    return {
        "id": action.id,
        "action_id": action.action_id,
        "device_id": action.device_id,
        "action_type": action.action_type,
        "requested_by": action.requested_by,
        "requested_at": _iso(action.requested_at),
        "completed_at": _iso(action.completed_at),
        "status": action.status,
        "result_summary": action.result_summary,
    }


def _apk_payload(scan: APKScan) -> dict:
    details = {}
    for finding in scan.findings or []:
        if finding.get("title") == "Analysis details":
            details = finding.get("details", {})
    return {
        "id": scan.id,
        "filename": scan.filename,
        "sha256": scan.hash,
        "package_name": scan.package_name,
        "version_name": scan.version_name,
        "version_code": scan.version_code,
        "scan_time": _iso(scan.scan_time),
        "risk_score": scan.risk_score,
        "risk_level": scan.risk_level,
        "permissions": scan.permissions or [],
        "findings": [item for item in scan.findings or [] if item.get("title") != "Analysis details"],
        "details": details,
    }


def _web_payload(scan: WebScan) -> dict:
    return {
        "id": scan.id,
        "target": scan.target,
        "scan_time": _iso(scan.scan_time),
        "risk_score": scan.risk_score,
        "risk_level": scan.risk_level,
        "findings": scan.findings or [],
    }


def _web_finding_count(db: Session) -> int:
    scans = db.scalars(select(WebScan)).all()
    return sum(len(scan.findings or []) for scan in scans)


def _counts(db: Session) -> dict:
    return {
        "devices": db.scalar(select(func.count(Device.id))) or 0,
        "events": db.scalar(select(func.count(SecurityEvent.id))) or 0,
        "alerts": db.scalar(select(func.count(Alert.id))) or 0,
        "apk_scans": db.scalar(select(func.count(APKScan.id))) or 0,
        "web_scans": db.scalar(select(func.count(WebScan.id))) or 0,
    }


@router.get("/status")
def get_status(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    counts = _counts(db)
    active_alerts = (
        db.scalar(select(func.count(Alert.id)).where(Alert.status == "active")) or 0
    )

    return {
        "service": "Cyber Command Center",
        "status": "ok",
        "version": "1.0.0",
        "environment": "local-lab",
        "authenticated": request_is_authenticated(request, settings),
        "database": "ok",
        "counts": counts,
        "active_alerts": active_alerts,
        "message": "Cyber Command Center v1.0 is running.",
    }


@router.get("/devices")
def list_devices(db: Session = Depends(get_db)) -> dict:
    devices = db.scalars(select(Device).order_by(Device.last_seen.desc())).all()
    return {
        "items": [_device_payload(device) for device in devices],
        "summary": {
            "total": len(devices),
            "online": sum(1 for device in devices if device.status == "online"),
            "offline": sum(1 for device in devices if device.status == "offline"),
            "known": sum(1 for device in devices if device.known),
            "unknown": sum(1 for device in devices if not device.known),
        },
    }


@router.get("/network/scopes")
def network_scopes(settings: Settings = Depends(get_settings)) -> dict:
    return {"items": detect_local_networks(settings)}


@router.post("/network/scan")
def scan_network(
    payload: NetworkScanRequest,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    cidr = payload.cidr or (detect_local_networks(settings)[0])
    try:
        discovered = discover_devices(cidr, settings)
        result = record_scan(db, discovered)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    logger.info(
        "network_scan_completed",
        extra={"ccc_module": "network", "metadata": {"scope": cidr, "devices": result["seen"]}},
    )
    return {"scope": cidr, "result": result, "devices": discovered}


@router.patch("/devices/{device_id}/known")
def set_device_known(
    device_id: int,
    payload: DeviceKnownRequest,
    db: Session = Depends(get_db),
) -> dict:
    device = db.get(Device, device_id)
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found.")
    device.known = payload.known
    db.commit()
    db.refresh(device)
    logger.info(
        "device_marked_known" if device.known else "device_marked_unknown",
        extra={"ccc_module": "network", "metadata": {"device_id": device.id, "ip_address": device.ip_address}},
    )
    return _device_payload(device)


@router.get("/events")
def list_events(
    severity: str | None = Query(default=None),
    source: str | None = Query(default=None),
    q: str | None = Query(default=None, min_length=1),
    sort: str = Query(default="newest"),
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
) -> dict:
    query = select(SecurityEvent)
    if severity:
        query = query.where(func.upper(SecurityEvent.severity) == severity.upper())
    if source:
        query = query.where(func.lower(SecurityEvent.source) == source.lower())
    if q:
        like = f"%{q.strip()}%"
        query = query.where(
            or_(
                SecurityEvent.message.ilike(like),
                SecurityEvent.source.ilike(like),
                SecurityEvent.event_type.ilike(like),
            )
        )
    if sort not in {"newest", "oldest"}:
        raise HTTPException(status_code=400, detail="Invalid sort order.")
    order_by = SecurityEvent.timestamp.desc() if sort != "oldest" else SecurityEvent.timestamp.asc()
    events = db.scalars(query.order_by(order_by).limit(limit)).all()
    sources = db.scalars(select(SecurityEvent.source).distinct().order_by(SecurityEvent.source)).all()
    return {
        "items": [_event_payload(event) for event in events],
        "filters": {
            "severities": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
            "sources": list(sources),
        },
        "summary": {
            "total": db.scalar(select(func.count(SecurityEvent.id))) or 0,
            "limit": limit,
            "returned": len(events),
        },
    }


@router.get("/alerts")
def list_alerts(
    status_filter: str | None = Query(default=None, alias="status"),
    severity: str | None = Query(default=None),
    source: str | None = Query(default=None),
    q: str | None = Query(default=None, min_length=1),
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
) -> dict:
    query = select(Alert)
    if status_filter:
        query = query.where(Alert.status == status_filter)
    if severity:
        query = query.where(func.upper(Alert.severity) == severity.upper())
    if source:
        query = query.where(func.lower(Alert.source) == source.lower())
    if q:
        like = f"%{q.strip()}%"
        query = query.where(
            or_(
                Alert.title.ilike(like),
                Alert.description.ilike(like),
                Alert.source.ilike(like),
                Alert.rule_id.ilike(like),
            )
        )
    alerts = db.scalars(
        query.order_by(Alert.last_seen.desc(), Alert.timestamp.desc()).limit(limit)
    ).all()
    return {
        "items": [_alert_payload(alert) for alert in alerts],
        "filters": {
            "severities": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
            "statuses": ["active", "acknowledged", "resolved"],
            "sources": list(
                db.scalars(select(Alert.source).distinct().order_by(Alert.source)).all()
            ),
        },
        "summary": {
            "total": db.scalar(select(func.count(Alert.id))) or 0,
            "active": db.scalar(select(func.count(Alert.id)).where(Alert.status == "active")) or 0,
            "limit": limit,
            "returned": len(alerts),
        },
    }


@router.patch("/alerts/{alert_id}/acknowledge")
def acknowledge_alert(alert_id: int, db: Session = Depends(get_db)) -> dict:
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found.",
        )
    alert = acknowledge_alert_record(db, alert)
    return _alert_payload(alert)


@router.post("/alerts/{alert_id}/acknowledge")
def acknowledge_alert_post(alert_id: int, db: Session = Depends(get_db)) -> dict:
    return acknowledge_alert(alert_id, db)


@router.patch("/alerts/{alert_id}/resolve")
def resolve_alert(alert_id: int, db: Session = Depends(get_db)) -> dict:
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found.",
        )
    alert = resolve_alert_record(db, alert)
    return _alert_payload(alert)


@router.post("/alerts/{alert_id}/resolve")
def resolve_alert_post(alert_id: int, db: Session = Depends(get_db)) -> dict:
    return resolve_alert(alert_id, db)


@router.get("/apk")
def apk_guard_status(db: Session = Depends(get_db)) -> dict:
    scans = db.scalars(select(APKScan).order_by(APKScan.scan_time.desc())).all()
    return {"items": [_apk_payload(scan) for scan in scans]}


@router.post("/apk/scan")
async def scan_apk(
    request: Request,
    db: Session = Depends(get_db),
) -> dict:
    filename = request.headers.get("x-filename", "upload.apk")
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            too_large = int(content_length) > 60 * 1024 * 1024
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid content length.") from None
        if too_large:
            raise HTTPException(
                status_code=413,
                detail="APK upload is too large for the local lab limit.",
            )
    content = await request.body()
    try:
        analysis = analyze_apk(content, filename)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    stored_findings = list(analysis["findings"])
    stored_findings.append({"title": "Analysis details", "severity": "LOW", "details": analysis})
    scan = APKScan(
        filename=analysis["filename"],
        hash=analysis["sha256"],
        package_name=analysis["package_name"],
        version_name=analysis["version_name"],
        version_code=analysis["version_code"],
        risk_score=analysis["risk_score"],
        risk_level=analysis["risk_level"],
        permissions=analysis["permissions"],
        findings=stored_findings,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    logger.info(
        "apk_scan_completed",
        extra={"ccc_module": "apk", "metadata": {"scan_id": scan.id, "risk_level": scan.risk_level}},
    )
    create_event(
        db,
        event_type="APK_SCAN_COMPLETED",
        severity=analysis["risk_level"],
        source="apk",
        message=f"APK scan completed for {analysis['filename']} with {analysis['risk_level']} risk.",
        metadata={"apk_scan_id": scan.id, "risk_score": analysis["risk_score"]},
    )
    return _apk_payload(scan)


@router.get("/websec")
def websec_status(db: Session = Depends(get_db)) -> dict:
    scans = db.scalars(select(WebScan).order_by(WebScan.scan_time.desc())).all()
    return {"items": [_web_payload(scan) for scan in scans]}


@router.get("/websec/targets")
def websec_targets(settings: Settings = Depends(get_settings)) -> dict:
    return {"items": list(settings.authorized_scan_targets)}


@router.post("/websec/scan")
def scan_websec(
    payload: WebSecScanRequest,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    try:
        result = scan_target(payload.target, settings)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    scan = WebScan(
        target=result["target"],
        risk_score=result["risk_score"],
        risk_level=result["risk_level"],
        findings=result["findings"],
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    logger.info(
        "websec_scan_completed",
        extra={"ccc_module": "websec", "metadata": {"scan_id": scan.id, "risk_level": scan.risk_level}},
    )
    create_event(
        db,
        event_type="WEBSEC_SCAN_COMPLETED",
        severity=result["risk_level"],
        source="websec",
        message=f"WebSec scan completed for {result['target']} with {len(result['findings'])} findings.",
        metadata={"web_scan_id": scan.id, "highest_severity": result["highest_severity"]},
    )
    return _web_payload(scan)


@router.get("/crypto")
def crypto_status() -> dict:
    return {
        "module": "HashLab",
        "algorithm": "scrypt",
        "message": "Generate salted password verifiers and verify them without storing plaintext.",
    }


@router.post("/crypto/hash")
def hash_password(payload: HashRequest) -> dict:
    try:
        return generate_verifier(payload.password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/crypto/verify")
def verify_hash(payload: VerifyHashRequest) -> dict:
    try:
        return verify_password(payload.password, payload.verifier)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/stats")
def stats_status(db: Session = Depends(get_db)) -> dict:
    counts = _counts(db)
    web_findings = _web_finding_count(db)
    active_alerts = db.scalars(select(Alert).where(Alert.status == "active")).all()
    recent_events = db.scalars(
        select(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).limit(5)
    ).all()
    risk = calculate_lab_risk(db)
    return {
        "network_devices": counts["devices"],
        "apks_scanned": counts["apk_scans"],
        "web_findings": web_findings,
        "security_events": counts["events"],
        "active_alerts": len(active_alerts),
        "overall_lab_risk": risk["level"],
        "lab_risk_score": risk["score"],
        "risk_reasons": risk["reasons"],
        "recent_activity": [_event_payload(event) for event in recent_events],
    }


@router.get("/risk")
def get_risk(db: Session = Depends(get_db)) -> dict:
    return calculate_lab_risk(db)


@router.get("/risk/history")
def risk_history(
    limit: int = Query(default=20, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> dict:
    return get_risk_history(db, limit=limit, offset=offset)


@router.get("/timeline")
def get_timeline(
    item_type: str | None = Query(default=None, alias="type"),
    source: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    device_id: str | None = Query(default=None, max_length=64),
    start: datetime | None = Query(default=None),
    end: datetime | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> dict:
    items = build_timeline(db)
    filtered = filter_timeline(
        items,
        item_type=item_type,
        source=source,
        severity=severity,
        device_id=device_id,
        start=start,
        end=end,
    )
    total = len(filtered)
    paged = filtered[offset : offset + limit]
    return {
        "items": paged,
        "summary": {
            "total": total,
            "limit": limit,
            "offset": offset,
        },
    }


@router.get("/rules")
def list_detection_rules(db: Session = Depends(get_db)) -> dict:
    rules = list_rules(db)
    return {
        "items": [_rule_payload(rule) for rule in rules],
        "summary": {
            "total": len(rules),
            "enabled": sum(1 for rule in rules if rule.enabled),
        },
    }


@router.get("/rules/{rule_id}")
def get_detection_rule(rule_id: str, db: Session = Depends(get_db)) -> dict:
    rule = get_rule(db, rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="Detection rule not found.")
    return _rule_payload(rule)


@router.get("/settings")
def dashboard_settings(settings: Settings = Depends(get_settings)) -> dict:
    database_type = settings.database_url.split(":", 1)[0]
    return {
        "api_host": settings.api_host,
        "api_port": settings.api_port,
        "auth_enabled": settings.auth_enabled,
        "database_type": database_type,
        "log_level": settings.log_level,
        "network_monitor_interval_seconds": settings.network_monitor_interval_seconds,
        "network_scan_max_hosts": settings.network_scan_max_hosts,
        "authorized_network_ranges": list(settings.authorized_network_ranges),
        "authorized_scan_targets": list(settings.authorized_scan_targets),
        "alert_high_threshold": settings.alert_high_threshold,
        "alert_critical_threshold": settings.alert_critical_threshold,
        "auth_failure_threshold": settings.auth_failure_threshold,
        "auth_failure_window_minutes": settings.auth_failure_window_minutes,
        "cors_allowed_origins": list(settings.cors_allowed_origins),
        "private_tunnel_configured": bool(settings.private_tunnel_endpoint),
        "managed_device_pairing_ttl_seconds": settings.managed_device_pairing_ttl_seconds,
        "managed_device_heartbeat_interval_seconds": settings.managed_device_heartbeat_interval_seconds,
        "managed_device_offline_after_seconds": settings.managed_device_offline_after_seconds,
    }


@router.get("/tunnel")
def tunnel_status(settings: Settings = Depends(get_settings)) -> dict:
    parsed = urlparse(settings.private_tunnel_endpoint) if settings.private_tunnel_endpoint else None
    return {
        "mode": "private_tunnel" if parsed else "lan_only",
        "configured": parsed is not None and bool(parsed.scheme and parsed.netloc),
        "endpoint_host": parsed.hostname if parsed else None,
        "endpoint_scheme": parsed.scheme if parsed else None,
        "public_exposure_allowed": False,
        "note": "Use a private encrypted tunnel; never expose FastAPI port 8001 directly to the public internet.",
    }


@router.post("/pairing/request")
def request_pairing(
    payload: PairingRequest,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    if not rate_limiter.allow(
        f"pairing-request:{request.client.host if request.client else 'unknown'}", 10, 300
    ):
        raise HTTPException(status_code=429, detail="Too many pairing requests.")
    session, code = create_pairing_session(
        db, device_name=payload.device_name, device_id=payload.device_id, settings=settings
    )
    create_event(
        db,
        event_type="DEVICE_PAIRING_REQUESTED",
        severity="LOW",
        source="managed_device",
        message="A managed-device pairing session was created.",
        metadata={"session_id": session.session_id, "intended_device_id": payload.device_id},
    )
    return {
        "session_id": session.session_id,
        "pairing_code": code,
        "expires_at": _iso(session.expires_at),
        "one_time": True,
    }


@agent_router.post("/pairing/complete")
def finish_pairing(
    payload: PairingCompleteRequest,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    if not rate_limiter.allow(
        f"pairing-complete:{request.client.host if request.client else 'unknown'}", 8, 300
    ):
        raise HTTPException(status_code=429, detail="Too many pairing attempts.")
    if len(str(payload.os_info)) > 8000:
        raise HTTPException(status_code=413, detail="Device metadata is too large.")
    try:
        device, token = complete_pairing(
            db,
            pairing_code=payload.pairing_code,
            device_id=payload.device_id,
            device_name=payload.device_name,
            device_type=payload.device_type,
            platform=payload.platform,
            agent_version=payload.agent_version,
            os_info=payload.os_info,
            public_key_fingerprint=payload.public_key_fingerprint,
            settings=settings,
        )
    except HTTPException as exc:
        create_event(
            db,
            event_type="DEVICE_PAIRING_FAILED",
            severity="MEDIUM",
            source="managed_device",
            message="Managed-device pairing failed.",
            metadata={"device_id": payload.device_id, "status_code": exc.status_code},
            process_rules=False,
        )
        raise
    return {
        "device": _managed_device_payload(device),
        "device_token": token,
        "credential_expires_at": _iso(device.credential_expires_at),
        "token_returned_once": True,
    }


@router.get("/managed-devices")
def list_managed_devices(
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    mark_offline_devices(db, settings)
    devices = db.scalars(select(ManagedDevice).order_by(ManagedDevice.last_seen.desc())).all()
    items = []
    for device in devices:
        risk = calculate_device_risk(db, device.device_id)
        alerts = db.scalar(select(func.count(Alert.id)).where(Alert.managed_device_id == device.device_id, Alert.status == "active")) or 0
        items.append(_managed_device_payload(device, risk=risk, alert_count=alerts))
    return {
        "items": items,
        "summary": {
            "total": len(items),
            "active": sum(item["status"] == "ACTIVE" for item in items),
            "offline": sum(item["status"] == "OFFLINE" for item in items),
            "revoked": sum(item["revoked"] for item in items),
        },
    }


@router.get("/managed-devices/{device_id}")
def managed_device_detail(device_id: str, db: Session = Depends(get_db)) -> dict:
    device = db.scalar(select(ManagedDevice).where(ManagedDevice.device_id == device_id))
    if device is None:
        raise HTTPException(status_code=404, detail="Managed device not found.")
    risk = calculate_device_risk(db, device_id)
    alerts = db.scalar(select(func.count(Alert.id)).where(Alert.managed_device_id == device_id, Alert.status == "active")) or 0
    return _managed_device_payload(device, risk=risk, alert_count=alerts)


@router.post("/managed-devices/{device_id}/revoke")
def revoke_managed_device(device_id: str, db: Session = Depends(get_db)) -> dict:
    device = db.scalar(select(ManagedDevice).where(ManagedDevice.device_id == device_id))
    if device is None:
        raise HTTPException(status_code=404, detail="Managed device not found.")
    if device.status != "REVOKED":
        device.status = "REVOKED"
        device.pairing_status = "REVOKED"
        device.revoked_at = datetime.now()
        device.credential_hash = None
        db.commit()
        create_event(
            db,
            event_type="DEVICE_REVOKED",
            severity="HIGH",
            source="managed_device",
            message=f"Managed device {device.device_name} was revoked.",
            metadata={"managed_device_id": device.device_id},
        )
    return _managed_device_payload(device, risk=calculate_device_risk(db, device_id))


@router.post("/managed-devices/{device_id}/rotate-credential")
def rotate_managed_device_credential(device_id: str, db: Session = Depends(get_db), settings: Settings = Depends(get_settings)) -> dict:
    device = db.scalar(select(ManagedDevice).where(ManagedDevice.device_id == device_id))
    if device is None:
        raise HTTPException(status_code=404, detail="Managed device not found.")
    if device.status == "REVOKED":
        raise HTTPException(status_code=403, detail="Device is revoked.")
    token = secrets.token_urlsafe(32)
    device.credential_hash = _secret_hash(token)
    device.credential_expires_at = datetime.now() + timedelta(days=settings.managed_device_credential_ttl_days)
    db.commit()
    create_event(
        db,
        event_type="DEVICE_CREDENTIAL_ROTATED",
        severity="LOW",
        source="managed_device",
        message=f"Credentials rotated for managed device {device.device_name}.",
        metadata={"managed_device_id": device_id},
    )
    return {"device_id": device_id, "device_token": token, "credential_expires_at": _iso(device.credential_expires_at), "token_returned_once": True}


@router.get("/managed-devices/{device_id}/status")
def managed_device_status(device_id: str, db: Session = Depends(get_db), settings: Settings = Depends(get_settings)) -> dict:
    mark_offline_devices(db, settings)
    device = db.scalar(select(ManagedDevice).where(ManagedDevice.device_id == device_id))
    if device is None:
        raise HTTPException(status_code=404, detail="Managed device not found.")
    return _managed_device_payload(device, risk=calculate_device_risk(db, device_id))


@router.get("/managed-devices/{device_id}/risk")
def managed_device_risk(device_id: str, db: Session = Depends(get_db)) -> dict:
    try:
        return calculate_device_risk(db, device_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/managed-devices/{device_id}/events")
def managed_device_events(device_id: str, limit: int = Query(default=100, ge=1, le=500), db: Session = Depends(get_db)) -> dict:
    if db.scalar(select(ManagedDevice).where(ManagedDevice.device_id == device_id)) is None:
        raise HTTPException(status_code=404, detail="Managed device not found.")
    events = db.scalars(select(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).limit(limit * 3)).all()
    items = [_event_payload(event) for event in events if (event.event_metadata or {}).get("managed_device_id") == device_id][:limit]
    return {"items": items, "summary": {"returned": len(items), "limit": limit}}


@router.get("/managed-devices/{device_id}/alerts")
def managed_device_alerts(device_id: str, limit: int = Query(default=100, ge=1, le=500), db: Session = Depends(get_db)) -> dict:
    if db.scalar(select(ManagedDevice).where(ManagedDevice.device_id == device_id)) is None:
        raise HTTPException(status_code=404, detail="Managed device not found.")
    alerts = db.scalars(select(Alert).where(Alert.managed_device_id == device_id).order_by(Alert.last_seen.desc()).limit(limit)).all()
    return {"items": [_alert_payload(alert) for alert in alerts], "summary": {"returned": len(alerts), "limit": limit}}


@router.get("/managed-devices/{device_id}/actions")
def managed_device_actions(device_id: str, limit: int = Query(default=50, ge=1, le=100), db: Session = Depends(get_db)) -> dict:
    actions = db.scalars(select(RemoteAction).where(RemoteAction.device_id == device_id).order_by(RemoteAction.requested_at.desc()).limit(limit)).all()
    return {"items": [_remote_action_payload(action) for action in actions], "summary": {"returned": len(actions)}}


@router.post("/managed-devices/{device_id}/actions")
def request_managed_action(device_id: str, payload: RemoteActionRequest, db: Session = Depends(get_db)) -> dict:
    device = db.scalar(select(ManagedDevice).where(ManagedDevice.device_id == device_id))
    if device is None:
        raise HTTPException(status_code=404, detail="Managed device not found.")
    action_type = payload.action_type.upper()
    if action_type not in ALLOWED_REMOTE_ACTIONS:
        raise HTTPException(status_code=400, detail="Unknown or disallowed remote action.")
    if device.status == "REVOKED":
        raise HTTPException(status_code=403, detail="Device is revoked.")
    action = RemoteAction(
        action_id=uuid.uuid4().hex,
        device_id=device_id,
        action_type=action_type,
        requested_by=payload.requested_by,
        status="REQUESTED",
    )
    db.add(action)
    db.commit()
    db.refresh(action)
    create_event(
        db,
        event_type="REMOTE_ACTION_REQUESTED",
        severity="LOW",
        source="managed_device",
        message=f"Allowed remote action {action_type} requested for {device.device_name}.",
        metadata={"managed_device_id": device_id, "action_id": action.action_id, "action_type": action_type},
    )
    return _remote_action_payload(action)


@agent_router.get("/managed-devices/{device_id}/actions/pending")
def get_pending_actions(device_id: str, request: Request, db: Session = Depends(get_db)) -> dict:
    device = device_from_request(request, db)
    if device.device_id != device_id:
        raise HTTPException(status_code=403, detail="Device identity mismatch.")
    actions = db.scalars(select(RemoteAction).where(RemoteAction.device_id == device_id, RemoteAction.status == "REQUESTED").order_by(RemoteAction.requested_at.asc()).limit(20)).all()
    return {"items": [_remote_action_payload(action) for action in actions]}


@agent_router.patch("/managed-devices/{device_id}/actions/{action_id}")
def complete_managed_action(device_id: str, action_id: str, payload: RemoteActionResultRequest, request: Request, db: Session = Depends(get_db)) -> dict:
    device = device_from_request(request, db)
    if device.device_id != device_id:
        raise HTTPException(status_code=403, detail="Device identity mismatch.")
    action = db.scalar(select(RemoteAction).where(RemoteAction.action_id == action_id, RemoteAction.device_id == device_id))
    if action is None:
        raise HTTPException(status_code=404, detail="Remote action not found.")
    if payload.status.upper() not in {"COMPLETED", "FAILED", "REJECTED"}:
        raise HTTPException(status_code=400, detail="Invalid action result status.")
    action.status = payload.status.upper()
    action.result_summary = payload.result_summary
    action.completed_at = datetime.now()
    db.commit()
    create_event(
        db,
        event_type="REMOTE_ACTION_COMPLETED" if action.status == "COMPLETED" else "REMOTE_ACTION_REJECTED",
        severity="LOW" if action.status == "COMPLETED" else "MEDIUM",
        source="managed_device",
        message=f"Remote action {action.action_type} {action.status.lower()}.",
        metadata={"managed_device_id": device_id, "action_id": action_id, "action_type": action.action_type},
    )
    return _remote_action_payload(action)


@agent_router.post("/managed-devices/{device_id}/heartbeat")
def managed_device_heartbeat(device_id: str, payload: HeartbeatRequest, request: Request, db: Session = Depends(get_db)) -> dict:
    device = device_from_request(request, db)
    if device.device_id != device_id:
        raise HTTPException(status_code=403, detail="Device identity mismatch.")
    if len(str(payload.model_dump())) > 30000:
        raise HTTPException(status_code=413, detail="Heartbeat payload is too large.")
    heartbeat, duplicate = record_heartbeat(
        db, device, heartbeat_id=payload.heartbeat_id, system_info=payload.system_info,
        network_info=payload.network_info, health=payload.health,
    )
    return {"accepted": True, "duplicate": duplicate, "received_at": _iso(heartbeat.received_at), "status": device.status}


@agent_router.post("/managed-devices/{device_id}/telemetry")
def managed_device_telemetry(device_id: str, payload: TelemetryRequest, request: Request, db: Session = Depends(get_db)) -> dict:
    device = device_from_request(request, db)
    if device.device_id != device_id:
        raise HTTPException(status_code=403, detail="Device identity mismatch.")
    if len(str(payload.metadata)) > 12000:
        raise HTTPException(status_code=413, detail="Telemetry metadata is too large.")
    recent = db.scalars(select(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).limit(300)).all()
    if any(
        (event.event_metadata or {}).get("telemetry_id") == payload.telemetry_id
        and (event.event_metadata or {}).get("managed_device_id") == device_id
        for event in recent
    ):
        return {"accepted": True, "duplicate": True}
    severity = payload.severity.upper()
    if severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        raise HTTPException(status_code=400, detail="Invalid telemetry severity.")
    event = create_event(
        db,
        event_type=payload.event_type.upper(),
        severity=severity,
        source="managed_device",
        message=payload.message,
        metadata={**payload.metadata, "managed_device_id": device_id, "telemetry_id": payload.telemetry_id},
    )
    device.last_seen = datetime.now()
    device.status = "ACTIVE"
    db.commit()
    return {"accepted": True, "duplicate": False, "event_id": event.id, "device_status": device.status}
