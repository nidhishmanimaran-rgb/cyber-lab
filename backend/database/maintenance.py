"""Non-destructive SQLite maintenance helpers for local release operations."""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path


def verify_sqlite_file(path: Path) -> dict[str, str]:
    path = path.resolve()
    if not path.is_file():
        raise RuntimeError(f"SQLite database file does not exist: {path}")
    connection = sqlite3.connect(path)
    try:
        result = connection.execute("PRAGMA quick_check").fetchone()
    finally:
        connection.close()
    if not result or result[0] != "ok":
        raise RuntimeError(f"SQLite integrity check failed for {path}.")
    return {"path": str(path), "integrity": "ok"}


def backup_sqlite_file(source: Path, destination: Path) -> Path:
    verify_sqlite_file(source)
    destination = destination.resolve()
    if destination.exists():
        raise FileExistsError(f"Backup destination already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    source_db = sqlite3.connect(source.resolve())
    destination_db = sqlite3.connect(destination)
    try:
        source_db.backup(destination_db)
    finally:
        destination_db.close()
        source_db.close()
    verify_sqlite_file(destination)
    return destination


def restore_sqlite_file(source: Path, destination: Path, *, replace: bool = False) -> Path:
    verify_sqlite_file(source)
    destination = destination.resolve()
    if destination.exists() and not replace:
        raise FileExistsError("Restore destination exists. Pass --replace only after stopping the backend.")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".restore.tmp")
    if temporary.exists():
        raise FileExistsError(f"Temporary restore file already exists: {temporary}")
    try:
        source_db = sqlite3.connect(source.resolve())
        destination_db = sqlite3.connect(temporary)
        try:
            source_db.backup(destination_db)
        finally:
            destination_db.close()
            source_db.close()
        verify_sqlite_file(temporary)
        if destination.exists() and not replace:
            raise FileExistsError("Restore destination exists.")
        os.replace(temporary, destination)
    finally:
        if temporary.exists():
            temporary.unlink()
    return destination
