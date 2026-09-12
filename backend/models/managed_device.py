from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from backend.database.session import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ManagedDevice(Base):
    __tablename__ = "managed_devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    device_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    device_name: Mapped[str] = mapped_column(String(120), index=True)
    device_type: Mapped[str] = mapped_column(String(40), default="computer")
    platform: Mapped[str] = mapped_column(String(40), default="windows")
    os_info: Mapped[dict] = mapped_column(JSON, default=dict)
    agent_version: Mapped[str] = mapped_column(String(40), default="unknown")
    public_key_fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True)
    credential_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    credential_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(32), default="OFFLINE", index=True)
    pairing_status: Mapped[str] = mapped_column(String(32), default="PAIRED", index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    network_info: Mapped[dict] = mapped_column(JSON, default=dict)
    system_info: Mapped[dict] = mapped_column(JSON, default=dict)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)


class PairingSession(Base):
    __tablename__ = "pairing_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    session_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    code_hash: Mapped[str] = mapped_column(String(128), index=True)
    intended_device_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    intended_device_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(24), default="ACTIVE", index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)


class DeviceHeartbeat(Base):
    __tablename__ = "device_heartbeats"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    heartbeat_id: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    device_id: Mapped[str] = mapped_column(String(64), index=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    status: Mapped[str] = mapped_column(String(32), default="ACTIVE")
    payload: Mapped[dict] = mapped_column(JSON, default=dict)


class DeviceRiskSnapshot(Base):
    __tablename__ = "device_risk_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    device_id: Mapped[str] = mapped_column(String(64), index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    score: Mapped[int] = mapped_column(Integer, default=0)
    level: Mapped[str] = mapped_column(String(32), default="LOW")
    trend: Mapped[str] = mapped_column(String(16), default="STABLE")
    change: Mapped[int] = mapped_column(Integer, default=0)
    contributors: Mapped[list] = mapped_column(JSON, default=list)
    reasons: Mapped[list] = mapped_column(JSON, default=list)


class RemoteAction(Base):
    __tablename__ = "remote_actions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    action_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    device_id: Mapped[str] = mapped_column(String(64), index=True)
    action_type: Mapped[str] = mapped_column(String(64), index=True)
    requested_by: Mapped[str] = mapped_column(String(120), default="api")
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="REQUESTED", index=True)
    result_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    audit_metadata: Mapped[dict] = mapped_column(JSON, default=dict)
