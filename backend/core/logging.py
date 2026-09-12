from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any


SENSITIVE_METADATA_KEYS = {
    "api_token",
    "authorization",
    "credential",
    "credential_hash",
    "device_token",
    "pairing_code",
    "password",
    "private_key",
    "secret",
    "token",
    "verifier",
}
_BEARER_VALUE = re.compile(r"(?i)(bearer\s+)[^\s,;]+")


def _redact(value: Any, *, key: str | None = None) -> Any:
    if key and any(marker in key.lower() for marker in SENSITIVE_METADATA_KEYS):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(item_key): _redact(item_value, key=str(item_key)) for item_key, item_value in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(item) for item in value]
    if isinstance(value, str):
        return _BEARER_VALUE.sub(r"\1[REDACTED]", value)
    return value


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat(),
            "module": getattr(record, "ccc_module", record.name),
            "level": record.levelname,
            "message": _redact(record.getMessage()),
        }
        metadata = getattr(record, "metadata", None)
        if metadata:
            payload["metadata"] = _redact(metadata)
        if record.exc_info:
            payload["exception"] = _redact(self.formatException(record.exc_info))
        return json.dumps(payload, ensure_ascii=True)


def configure_logging(level: str = "INFO") -> None:
    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root_logger.addHandler(handler)
    root_logger.setLevel(level)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
