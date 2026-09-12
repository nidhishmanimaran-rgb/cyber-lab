from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from backend.database.session import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class APKScan(Base):
    __tablename__ = "apk_scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    filename: Mapped[str] = mapped_column(String(255))
    hash: Mapped[str] = mapped_column(String(64), index=True)
    package_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    version_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    version_code: Mapped[str | None] = mapped_column(String(100), nullable=True)
    scan_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    risk_level: Mapped[str] = mapped_column(String(32), default="LOW")
    permissions: Mapped[list] = mapped_column(JSON, default=list)
    findings: Mapped[list] = mapped_column(JSON, default=list)
