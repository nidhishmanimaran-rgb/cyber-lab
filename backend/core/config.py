from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse


def _load_dotenv(path: Path = Path(".env")) -> None:
    if not path.exists():
        return

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc


def _env_list(name: str, default: list[str]) -> list[str]:
    value = os.getenv(name)
    if value is None:
        return default
    return [item.strip() for item in value.split(",") if item.strip()]


@dataclass(frozen=True)
class Settings:
    api_host: str = "127.0.0.1"
    api_port: int = 8001
    database_url: str = "sqlite:///./data/cyber_command_center.sqlite3"
    log_level: str = "INFO"
    auth_enabled: bool = False
    api_token: str = ""
    network_monitor_interval_seconds: int = 60
    network_scan_max_hosts: int = 64
    authorized_network_ranges: tuple[str, ...] = ()
    authorized_scan_targets: tuple[str, ...] = (
        "http://127.0.0.1:8000",
        "http://localhost:8000",
    )
    alert_high_threshold: int = 50
    alert_critical_threshold: int = 75
    auth_failure_threshold: int = 5
    auth_failure_window_minutes: int = 10
    cors_allowed_origins: tuple[str, ...] = (
        "http://127.0.0.1:8001",
        "http://localhost:8001",
    )
    managed_device_pairing_ttl_seconds: int = 300
    managed_device_heartbeat_interval_seconds: int = 30
    managed_device_offline_after_seconds: int = 120
    managed_device_credential_ttl_days: int = 90
    private_tunnel_endpoint: str = ""


def generate_api_token(byte_length: int = 32) -> str:
    if byte_length < 16:
        raise ValueError("Token length must be at least 16 bytes.")
    return secrets.token_urlsafe(byte_length)


def _validate_host(host: str) -> None:
    if host in {"127.0.0.1", "0.0.0.0", "localhost"}:
        return
    # Allow explicit private IPv4 addresses, including Tailscale's CGNAT range,
    # and reject obvious public binding mistakes.
    parts = host.split(".")
    if len(parts) == 4 and all(part.isdigit() for part in parts):
        octets = [int(part) for part in parts]
        if octets[0] == 10:
            return
        if octets[0] == 192 and octets[1] == 168:
            return
        if octets[0] == 172 and 16 <= octets[1] <= 31:
            return
        if octets[0] == 100 and 64 <= octets[1] <= 127:
            return
    raise ValueError(
        "CCC_API_HOST must be localhost, 0.0.0.0, or a private LAN address "
        "including a Tailscale address."
    )


def _validate_database_url(database_url: str) -> None:
    parsed = urlparse(database_url)
    if parsed.scheme != "sqlite":
        raise ValueError("Only SQLite database URLs are supported in this lab.")
    if not database_url.startswith("sqlite:///"):
        raise ValueError("CCC_DATABASE_URL must be a valid sqlite:/// URL.")


def validate_settings(settings: "Settings") -> None:
    _validate_host(settings.api_host)
    if not 1 <= settings.api_port <= 65535:
        raise ValueError("CCC_API_PORT must be between 1 and 65535.")
    _validate_database_url(settings.database_url)
    if settings.auth_enabled and not settings.api_token:
        raise ValueError("CCC_AUTH_ENABLED is true but CCC_API_TOKEN is empty.")
    if settings.log_level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
        raise ValueError("CCC_LOG_LEVEL must be a standard Python logging level.")
    if not 1 <= settings.network_monitor_interval_seconds <= 3600:
        raise ValueError("CCC_NETWORK_MONITOR_INTERVAL_SECONDS must be between 1 and 3600.")
    if not 1 <= settings.network_scan_max_hosts <= 512:
        raise ValueError("CCC_NETWORK_SCAN_MAX_HOSTS must be between 1 and 512.")
    if not 0 <= settings.alert_high_threshold <= settings.alert_critical_threshold <= 100:
        raise ValueError("Alert thresholds must be between 0 and 100 with HIGH not exceeding CRITICAL.")
    if not 1 <= settings.auth_failure_threshold <= 100 or not 1 <= settings.auth_failure_window_minutes <= 1440:
        raise ValueError("Authentication failure limits are outside the supported range.")
    if not 60 <= settings.managed_device_pairing_ttl_seconds <= 3600:
        raise ValueError("CCC_PAIRING_TTL_SECONDS must be between 60 and 3600.")
    if not 1 <= settings.managed_device_heartbeat_interval_seconds <= 3600:
        raise ValueError("CCC_HEARTBEAT_INTERVAL_SECONDS must be between 1 and 3600.")
    if settings.managed_device_offline_after_seconds < settings.managed_device_heartbeat_interval_seconds:
        raise ValueError("CCC_DEVICE_OFFLINE_AFTER_SECONDS must not be shorter than the heartbeat interval.")
    if not 1 <= settings.managed_device_credential_ttl_days <= 3650:
        raise ValueError("CCC_DEVICE_CREDENTIAL_TTL_DAYS must be between 1 and 3650.")
    for origin in settings.cors_allowed_origins:
        parsed = urlparse(origin)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password:
            raise ValueError("CCC_CORS_ALLOWED_ORIGINS must contain valid origin URLs without credentials.")
    if settings.private_tunnel_endpoint:
        tunnel = urlparse(settings.private_tunnel_endpoint)
        if tunnel.scheme != "https" or not tunnel.netloc or tunnel.username or tunnel.password:
            raise ValueError("CCC_PRIVATE_TUNNEL_ENDPOINT must be an https URL without embedded credentials.")


@lru_cache
def get_settings() -> Settings:
    _load_dotenv()
    return Settings(
        api_host=os.getenv("CCC_API_HOST", "127.0.0.1"),
        api_port=_env_int("CCC_API_PORT", 8001),
        database_url=os.getenv(
            "CCC_DATABASE_URL", "sqlite:///./data/cyber_command_center.sqlite3"
        ),
        log_level=os.getenv("CCC_LOG_LEVEL", "INFO").upper(),
        auth_enabled=_env_bool("CCC_AUTH_ENABLED", False),
        api_token=os.getenv("CCC_API_TOKEN", ""),
        network_monitor_interval_seconds=_env_int(
            "CCC_NETWORK_MONITOR_INTERVAL_SECONDS", 60
        ),
        network_scan_max_hosts=_env_int("CCC_NETWORK_SCAN_MAX_HOSTS", 64),
        authorized_network_ranges=tuple(
            _env_list("CCC_AUTHORIZED_NETWORK_RANGES", [])
        ),
        authorized_scan_targets=tuple(
            _env_list(
                "CCC_AUTHORIZED_SCAN_TARGETS",
                ["http://127.0.0.1:8000", "http://localhost:8000"],
            )
        ),
        alert_high_threshold=_env_int("CCC_ALERT_HIGH_THRESHOLD", 50),
        alert_critical_threshold=_env_int("CCC_ALERT_CRITICAL_THRESHOLD", 75),
        auth_failure_threshold=_env_int("CCC_AUTH_FAILURE_THRESHOLD", 5),
        auth_failure_window_minutes=_env_int("CCC_AUTH_FAILURE_WINDOW_MINUTES", 10),
        cors_allowed_origins=tuple(
            _env_list(
                "CCC_CORS_ALLOWED_ORIGINS",
                ["http://127.0.0.1:8001", "http://localhost:8001"],
            )
        ),
        managed_device_pairing_ttl_seconds=_env_int("CCC_PAIRING_TTL_SECONDS", 300),
        managed_device_heartbeat_interval_seconds=_env_int("CCC_HEARTBEAT_INTERVAL_SECONDS", 30),
        managed_device_offline_after_seconds=_env_int("CCC_DEVICE_OFFLINE_AFTER_SECONDS", 120),
        managed_device_credential_ttl_days=_env_int("CCC_DEVICE_CREDENTIAL_TTL_DAYS", 90),
        private_tunnel_endpoint=os.getenv("CCC_PRIVATE_TUNNEL_ENDPOINT", ""),
    )
