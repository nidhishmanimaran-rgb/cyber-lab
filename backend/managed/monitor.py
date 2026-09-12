from __future__ import annotations

import asyncio
from backend.core.logging import get_logger
from collections.abc import Awaitable, Callable

from backend.core.config import Settings
from backend.database.session import SessionLocal
from backend.managed.service import mark_offline_devices

logger = get_logger("backend.managed.monitor")


def run_offline_check(settings: Settings) -> list[str]:
    db = SessionLocal()
    try:
        return mark_offline_devices(db, settings)
    finally:
        db.close()


async def monitor_managed_devices(
    settings: Settings,
    stop_event: asyncio.Event,
    on_transition: Callable[[list[str]], Awaitable[None]] | None = None,
) -> None:
    interval = max(1, min(settings.managed_device_heartbeat_interval_seconds, 300))
    while not stop_event.is_set():
        try:
            changed = await asyncio.to_thread(run_offline_check, settings)
        except Exception:
            logger.exception("managed_device_monitor_iteration_failed", extra={"ccc_module": "managed_device"})
            changed = []
        if changed and on_transition is not None:
            await on_transition(changed)
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval)
        except asyncio.TimeoutError:
            continue
