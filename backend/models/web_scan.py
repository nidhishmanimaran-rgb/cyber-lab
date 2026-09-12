from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from backend.database.session import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class WebScan(Base):
    __tablename__ = "web_scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    target: Mapped[str] = mapped_column(String(2048), index=True)
    scan_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    risk_level: Mapped[str] = mapped_column(String(32), default="LOW")
    findings: Mapped[list] = mapped_column(JSON, default=list)
