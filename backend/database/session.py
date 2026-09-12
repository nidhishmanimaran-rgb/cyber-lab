from __future__ import annotations

import sqlite3
from pathlib import Path

from sqlalchemy import inspect, text
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from backend.core.config import get_settings


SCHEMA_VERSION = "1.0.0"
REQUIRED_TABLES = {
    "alerts",
    "apk_scans",
    "detection_rules",
    "device_heartbeats",
    "device_risk_snapshots",
    "devices",
    "managed_devices",
    "pairing_sessions",
    "remote_actions",
    "risk_snapshots",
    "security_events",
    "web_scans",
}


class Base(DeclarativeBase):
    pass


def _sqlite_path_from_url(database_url: str) -> Path | None:
    if database_url.startswith("sqlite:///"):
        raw_path = database_url.replace("sqlite:///", "", 1)
        if raw_path in {":memory:", ""}:
            return None
        return Path(raw_path)
    return None


settings = get_settings()
db_path = _sqlite_path_from_url(settings.database_url)
if db_path is not None:
    db_path.parent.mkdir(parents=True, exist_ok=True)

engine = create_engine(
    settings.database_url,
    connect_args={"check_same_thread": False}
    if settings.database_url.startswith("sqlite")
    else {},
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def init_db() -> None:
    from backend import models  # noqa: F401

    Base.metadata.create_all(bind=engine)
    _sync_sqlite_columns()
    _record_schema_version()
    verify_database()
    from backend.detection.rules import seed_detection_rules

    db = SessionLocal()
    try:
        seed_detection_rules(db)
    finally:
        db.close()


def _sync_sqlite_columns() -> None:
    if not settings.database_url.startswith("sqlite"):
        return
    additions = {
        "apk_scans": {
            "package_name": "VARCHAR(255)",
            "version_name": "VARCHAR(100)",
            "version_code": "VARCHAR(100)",
        },
        "web_scans": {
            "risk_level": "VARCHAR(32) DEFAULT 'LOW'",
        },
        "alerts": {
            "last_seen": "DATETIME",
            "rule_id": "VARCHAR(100)",
            "rule_metadata": "JSON DEFAULT '{}'",
            "repeat_count": "INTEGER DEFAULT 1",
            "risk_points": "INTEGER DEFAULT 0",
            "cooldown_until": "DATETIME",
            "acknowledged_at": "DATETIME",
            "resolved_at": "DATETIME",
            "managed_device_id": "VARCHAR(64)",
        },
        "devices": {
            "services": "JSON DEFAULT '[]'",
        },
    }
    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())
    with engine.begin() as connection:
        for table, columns in additions.items():
            if table not in existing_tables:
                continue
            existing_columns = {column["name"] for column in inspector.get_columns(table)}
            for name, ddl in columns.items():
                if name not in existing_columns:
                    connection.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"))


def _record_schema_version() -> None:
    """Maintain a tiny migration ledger; schema changes remain additive only."""
    with engine.begin() as connection:
        connection.execute(
            text(
                "CREATE TABLE IF NOT EXISTS ccc_schema_metadata "
                "(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
        )
        connection.execute(
            text(
                "INSERT INTO ccc_schema_metadata(key, value) VALUES ('schema_version', :version) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value"
            ),
            {"version": SCHEMA_VERSION},
        )


def database_file_path() -> Path:
    path = _sqlite_path_from_url(settings.database_url)
    if path is None:
        raise RuntimeError("Database maintenance requires a file-backed SQLite database.")
    return path.resolve()


def verify_database() -> dict[str, str]:
    """Validate the local SQLite file and expected application tables without mutating data."""
    path = database_file_path()
    if not path.exists():
        raise RuntimeError(f"Database file does not exist: {path}")
    connection = sqlite3.connect(path)
    try:
        result = connection.execute("PRAGMA quick_check").fetchone()
    finally:
        connection.close()
    if not result or result[0] != "ok":
        raise RuntimeError("SQLite integrity check failed.")
    tables = set(inspect(engine).get_table_names())
    missing = sorted(REQUIRED_TABLES - tables)
    if missing:
        raise RuntimeError(f"Database schema is incomplete; missing tables: {', '.join(missing)}")
    return {"database": "ok", "schema_version": SCHEMA_VERSION, "integrity": "ok"}


def get_db():
    db: Session = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
