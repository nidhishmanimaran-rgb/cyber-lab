from __future__ import annotations

import hmac
import threading
import time
from collections import defaultdict, deque

from fastapi import Depends, HTTPException, Request, status

from backend.core.config import Settings, get_settings
from backend.core.logging import get_logger


PUBLIC_PATHS = {"/api/status"}
RATE_LIMITS: dict[str, tuple[int, int]] = {
    "/api/network/scan": (6, 300),
    "/api/apk/scan": (4, 300),
    "/api/websec/scan": (4, 300),
    "/api/crypto/hash": (12, 60),
    "/api/crypto/verify": (30, 60),
    "/api/pairing/request": (10, 300),
    "/api/pairing/complete": (8, 300),
}


class InMemoryRateLimiter:
    def __init__(self) -> None:
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str, limit: int, window_seconds: int) -> bool:
        now = time.monotonic()
        with self._lock:
            bucket = self._events[key]
            while bucket and now - bucket[0] > window_seconds:
                bucket.popleft()
            if len(bucket) >= limit:
                return False
            bucket.append(now)
            return True


rate_limiter = InMemoryRateLimiter()
logger = get_logger("backend.security")


def reset_rate_limiter() -> None:
    with rate_limiter._lock:
        rate_limiter._events.clear()


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _extract_token(request: Request) -> str:
    authorization = request.headers.get("authorization", "")
    if authorization.lower().startswith("bearer "):
        return authorization.split(" ", 1)[1].strip()
    return request.headers.get("x-api-key", "").strip()


def _is_rate_limited(request: Request) -> bool:
    path = request.url.path
    if request.method == "POST" and path.endswith("/actions"):
        limit, window = (20, 60)
    elif request.method == "POST" and (path.endswith("/revoke") or path.endswith("/rotate-credential")):
        limit, window = (10, 300)
    else:
        limit, window = RATE_LIMITS.get(path, (60, 60))
    key = f"{_client_ip(request)}:{path}"
    return not rate_limiter.allow(key, limit, window)


def _record_auth_failure(request: Request) -> None:
    try:
        from backend.database.session import SessionLocal
        from backend.detection.engine import create_event

        db = SessionLocal()
        try:
            create_event(
                db,
                event_type="AUTH_FAILURE",
                severity="MEDIUM",
                source="auth",
                message="Invalid or missing API key.",
                metadata={
                    "client": request.client.host if request.client else "unknown",
                    "path": request.url.path,
                },
            )
        finally:
            db.close()
        logger.warning(
            "authentication_failed",
            extra={
                "ccc_module": "auth",
                "metadata": {"client": _client_ip(request), "path": request.url.path},
            },
        )
    except Exception:
        return


def _record_rate_limit(request: Request) -> None:
    try:
        from backend.database.session import SessionLocal
        from backend.detection.engine import create_event

        db = SessionLocal()
        try:
            create_event(
                db,
                event_type="RATE_LIMITED",
                severity="LOW",
                source="api",
                message="Request rate limit exceeded.",
                metadata={
                    "client": _client_ip(request),
                    "path": request.url.path,
                },
            )
        finally:
            db.close()
        logger.warning(
            "rate_limited",
            extra={
                "ccc_module": "auth",
                "metadata": {"client": _client_ip(request), "path": request.url.path},
            },
        )
    except Exception:
        return


def require_api_key(
    request: Request,
    settings: Settings = Depends(get_settings),
) -> None:
    if request.url.path in PUBLIC_PATHS:
        return
    if _is_rate_limited(request):
        _record_rate_limit(request)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests.",
        )
    if not settings.auth_enabled:
        return
    if not settings.api_token:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="API authentication is enabled but no token is configured.",
        )

    supplied = _extract_token(request)
    if not hmac.compare_digest(supplied, settings.api_token):
        if not rate_limiter.allow(
            f"auth:{_client_ip(request)}",
            5,
            60,
        ):
            _record_rate_limit(request)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many authentication failures.",
            )
        _record_auth_failure(request)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key.",
        )


def request_is_authenticated(request: Request, settings: Settings | None = None) -> bool:
    settings = settings or get_settings()
    if not settings.auth_enabled:
        return False
    supplied = _extract_token(request)
    return bool(supplied and hmac.compare_digest(supplied, settings.api_token))
