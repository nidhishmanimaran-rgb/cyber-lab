"""Back up, verify, or restore the configured local Cyber Command Center database."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.database.maintenance import backup_sqlite_file, restore_sqlite_file, verify_sqlite_file
from backend.database.session import database_file_path, init_db, verify_database


def _backup_name() -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return Path("backups") / f"cyber_command_center-{stamp}.sqlite3"


def main() -> None:
    parser = argparse.ArgumentParser(description="Safe SQLite maintenance for Cyber Command Center.")
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("initialize", help="create additive schema updates and validate the configured database")
    subcommands.add_parser("verify", help="run SQLite and application schema integrity checks")
    backup = subcommands.add_parser("backup", help="create a verified backup without modifying the source database")
    backup.add_argument("--destination", type=Path, default=None)
    restore = subcommands.add_parser("restore", help="restore a verified backup after the backend is stopped")
    restore.add_argument("--source", type=Path, required=True)
    restore.add_argument("--destination", type=Path, default=None)
    restore.add_argument("--replace", action="store_true", help="allow replacing an existing destination database")
    args = parser.parse_args()

    if args.command == "initialize":
        init_db()
        print("DATABASE_INITIALIZED")
        return
    if args.command == "verify":
        print(verify_database())
        return
    if args.command == "backup":
        destination = args.destination or _backup_name()
        print(backup_sqlite_file(database_file_path(), destination))
        return
    destination = args.destination or database_file_path()
    print(restore_sqlite_file(args.source, destination, replace=args.replace))


if __name__ == "__main__":
    main()
