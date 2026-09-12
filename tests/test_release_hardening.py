import json
import logging

import pytest

from backend.core.config import Settings, validate_settings
from backend.core.logging import JsonFormatter
from backend.database.maintenance import backup_sqlite_file, restore_sqlite_file, verify_sqlite_file
from backend.database.session import database_file_path, init_db, verify_database


def test_database_integrity_backup_and_restore_are_non_destructive(tmp_path):
    init_db()
    assert verify_database()["integrity"] == "ok"

    backup = backup_sqlite_file(database_file_path(), tmp_path / "backup.sqlite3")
    assert verify_sqlite_file(backup)["integrity"] == "ok"

    restored = restore_sqlite_file(backup, tmp_path / "restored.sqlite3")
    assert verify_sqlite_file(restored)["integrity"] == "ok"
    with pytest.raises(FileExistsError):
        backup_sqlite_file(database_file_path(), backup)


def test_release_configuration_rejects_unsafe_ranges_and_tunnel_urls():
    validate_settings(Settings(api_host="100.64.12.34"))
    with pytest.raises(ValueError, match="NETWORK_SCAN_MAX_HOSTS"):
        validate_settings(Settings(network_scan_max_hosts=513))
    with pytest.raises(ValueError, match="OFFLINE"):
        validate_settings(
            Settings(
                managed_device_heartbeat_interval_seconds=60,
                managed_device_offline_after_seconds=30,
            )
        )
    with pytest.raises(ValueError, match="PRIVATE_TUNNEL_ENDPOINT"):
        validate_settings(Settings(private_tunnel_endpoint="http://private-tunnel.local"))


def test_json_logs_redact_sensitive_values():
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="Authorization Bearer token-value",
        args=(),
        exc_info=None,
    )
    record.metadata = {"api_token": "secret-value", "device_id": "safe-device"}
    payload = json.loads(JsonFormatter().format(record))
    assert "token-value" not in payload["message"]
    assert payload["metadata"]["api_token"] == "[REDACTED]"
    assert payload["metadata"]["device_id"] == "safe-device"
