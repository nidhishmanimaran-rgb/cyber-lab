from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.core.config import Settings, get_settings
from backend.core.security import rate_limiter
from backend.detection.engine import create_event
from backend.models import DeviceHeartbeat, ManagedDevice, PairingSession


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _secret_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _is_rate_limited(request: Request, bucket: str, limit: int, window: int) -> bool:
    client = request.client.host if request.client else "unknown"
    return not rate_limiter.allow(f"managed:{bucket}:{client}", limit, window)


def create_pairing_session(
    db: Session,
    *,
    device_name: str | None,
    device_id: str | None,
    settings: Settings | None = None,
) -> tuple[PairingSession, str]:
    settings = settings or get_settings()
    code = secrets.token_urlsafe(12)
    session = PairingSession(
        session_id=uuid.uuid4().hex,
        code_hash=_secret_hash(code),
        intended_device_id=device_id,
        intended_device_name=device_name,
        expires_at=utc_now() + timedelta(seconds=settings.managed_device_pairing_ttl_seconds),
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    return session, code


def complete_pairing(
    db: Session,
    *,
    pairing_code: str,
    device_id: str,
    device_name: str,
    device_type: str,
    platform: str,
    agent_version: str,
    os_info: dict,
    public_key_fingerprint: str | None,
    settings: Settings | None = None,
) -> tuple[ManagedDevice, str]:
    settings = settings or get_settings()
    now = utc_now()
    sessions = db.scalars(
        select(PairingSession).where(PairingSession.status == "ACTIVE").order_by(PairingSession.created_at.desc())
    ).all()
    matched = next((item for item in sessions if hmac.compare_digest(item.code_hash, _secret_hash(pairing_code))), None)
    if matched is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid pairing code.")
    matched.attempts = (matched.attempts or 0) + 1
    if matched.expires_at.replace(tzinfo=timezone.utc) <= now:
        matched.status = "EXPIRED"
        db.commit()
        raise HTTPException(status_code=status.HTTP_410_GONE, detail="Pairing code expired.")
    if matched.used_at is not None or matched.status != "ACTIVE":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Pairing code has already been used.")
    if matched.intended_device_id and matched.intended_device_id != device_id:
        db.commit()
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Pairing code is for another device.")
    if db.scalar(select(ManagedDevice).where(ManagedDevice.device_id == device_id)) is not None:
        db.commit()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Device is already registered.")

    token = secrets.token_urlsafe(32)
    device = ManagedDevice(
        device_id=device_id,
        device_name=device_name,
        device_type=device_type,
        platform=platform,
        os_info=os_info,
        agent_version=agent_version,
        public_key_fingerprint=public_key_fingerprint,
        credential_hash=_secret_hash(token),
        credential_expires_at=now + timedelta(days=settings.managed_device_credential_ttl_days),
        status="OFFLINE",
        pairing_status="PAIRED",
    )
    matched.status = "USED"
    matched.used_at = now
    db.add(device)
    db.commit()
    db.refresh(device)
    create_event(
        db,
        event_type="DEVICE_PAIRED",
        severity="LOW",
        source="managed_device",
        message=f"Managed device {device.device_name} was paired.",
        metadata={"managed_device_id": device.device_id, "device_name": device.device_name},
    )
    return device, token


def authenticate_device(db: Session, device_id: str, token: str) -> ManagedDevice:
    device = db.scalar(select(ManagedDevice).where(ManagedDevice.device_id == device_id))
    if device is None or device.revoked_at is not None or device.status == "REVOKED":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Device is not authorized.")
    if not token or not device.credential_hash or not hmac.compare_digest(device.credential_hash, _secret_hash(token)):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid device credentials.")
    if device.credential_expires_at:
        expiry = device.credential_expires_at.replace(tzinfo=timezone.utc)
        if expiry <= utc_now():
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Device credentials expired.")
    return device


def device_from_request(request: Request, db: Session) -> ManagedDevice:
    device_id = request.headers.get("x-device-id", "").strip()
    token = request.headers.get("x-device-token", "").strip()
    client = request.client.host if request.client else "unknown"
    if not rate_limiter.allow(f"managed-auth:{client}", 20, 60):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many device authentication attempts.")
    if not device_id or not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Device credentials are required.")
    try:
        return authenticate_device(db, device_id, token)
    except HTTPException:
        try:
            create_event(
                db,
                event_type="DEVICE_AUTH_FAILURE",
                severity="MEDIUM",
                source="managed_device",
                message="Managed device authentication failed.",
                metadata={"managed_device_id": device_id[:64], "client": client},
                process_rules=False,
            )
        except Exception:
            db.rollback()
        raise


def record_heartbeat(
    db: Session,
    device: ManagedDevice,
    *,
    heartbeat_id: str,
    system_info: dict,
    network_info: dict,
    health: dict,
) -> tuple[DeviceHeartbeat, bool]:
    if len(heartbeat_id) > 80:
        raise HTTPException(status_code=400, detail="Invalid heartbeat id.")
    storage_heartbeat_id = hashlib.sha256(
        f"{device.device_id}:{heartbeat_id}".encode("utf-8")
    ).hexdigest()
    duplicate = db.scalar(select(DeviceHeartbeat).where(DeviceHeartbeat.heartbeat_id == storage_heartbeat_id))
    now = utc_now()
    if duplicate is not None:
        return duplicate, True
    was_offline = device.status == "OFFLINE"
    device.last_seen = now
    device.status = "ACTIVE"
    device.system_info = system_info
    device.network_info = network_info
    heartbeat = DeviceHeartbeat(
        device_id=device.device_id,
        heartbeat_id=storage_heartbeat_id,
        received_at=now,
        status="ACTIVE",
        payload={"health": health},
    )
    db.add(heartbeat)
    db.commit()
    db.refresh(heartbeat)
    if was_offline:
        create_event(
            db,
            event_type="DEVICE_ONLINE",
            severity="LOW",
            source="managed_device",
            message=f"Managed device {device.device_name} reconnected.",
            metadata={"managed_device_id": device.device_id},
        )
    return heartbeat, False


def mark_offline_devices(db: Session, settings: Settings | None = None) -> list[str]:
    settings = settings or get_settings()
    cutoff = utc_now() - timedelta(seconds=settings.managed_device_offline_after_seconds)
    devices = db.scalars(
        select(ManagedDevice).where(
            ManagedDevice.status == "ACTIVE",
            ManagedDevice.last_seen.is_not(None),
            ManagedDevice.last_seen < cutoff,
        )
    ).all()
    changed: list[str] = []
    for device in devices:
        device.status = "OFFLINE"
        changed.append(device.device_id)
    if changed:
        db.commit()
        for device_id in changed:
            device = db.scalar(select(ManagedDevice).where(ManagedDevice.device_id == device_id))
            if device:
                create_event(
                    db,
                    event_type="DEVICE_OFFLINE",
                    severity="MEDIUM",
                    source="managed_device",
                    message=f"Managed device {device.device_name} is unreachable.",
                    metadata={"managed_device_id": device.device_id, "reason": "heartbeat_expired"},
                )
    return changed
