from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from backend.database.session import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class RiskSnapshot(Base):
    __tablename__ = "risk_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    score: Mapped[int] = mapped_column(Integer, default=0, index=True)
    level: Mapped[str] = mapped_column(String(32), default="LOW", index=True)
    trend: Mapped[str] = mapped_column(String(16), default="STABLE", index=True)
    change: Mapped[int] = mapped_column(Integer, default=0)
    signature: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    contributors: Mapped[list] = mapped_column(JSON, default=list)
    reasons: Mapped[list] = mapped_column(JSON, default=list)
