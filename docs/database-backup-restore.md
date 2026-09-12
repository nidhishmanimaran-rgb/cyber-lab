# Database Backup and Restore

The production database is the SQLite file configured by `CCC_DATABASE_URL`. Cyber Command Center never resets it automatically.

## Verify

```powershell
python .\scripts\database_maintenance.py verify
```

This runs SQLite `PRAGMA quick_check` and validates required application tables.

## Backup

```powershell
.\scripts\backup.ps1
```

The default destination is a timestamped file in `backups/`. A backup is copied with SQLite's backup API and validated before success is reported. Existing destinations are never overwritten.

## Restore

1. Stop the backend first.
2. Verify the backup with `python .\scripts\database_maintenance.py verify` after temporarily pointing `CCC_DATABASE_URL` to the backup, or use the restore command which verifies the source.
3. Restore explicitly:

```powershell
.\scripts\restore.ps1 -Source .\backups\cyber_command_center-YYYYMMDD-HHMMSS.sqlite3 -Replace
```

`-Replace` is intentionally required when restoring over the configured database. Restore writes and verifies a temporary database before replacement. Keep a separate backup of the current database before any restore.
