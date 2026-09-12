"""Runnable defensive Windows managed-device agent.

Run after pairing with::

    python -m agent.windows_agent --url http://192.168.1.2:8001 --pairing-code CODE

The agent only sends bounded system metadata and handles the server's
allowlisted read-only actions. It never executes command strings.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import platform
import socket
import threading
import time
import uuid
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from agent.credential_store import SecretStore, default_secret_store


AGENT_VERSION = "0.2.0"
logger = logging.getLogger("ccc.agent")


def _state_dir() -> Path:
    configured = os.getenv("CCC_AGENT_STATE_DIR")
    if configured:
        return Path(configured)
    local_app_data = os.getenv("LOCALAPPDATA")
    if local_app_data:
        return Path(local_app_data) / "CyberCommandCenter" / "agent"
    return Path.home() / ".cyber-command-center" / "agent"


class WindowsAgent:
    allowed_actions = {
        "REQUEST_HEARTBEAT",
        "REQUEST_SYSTEM_INFO",
        "REQUEST_NETWORK_STATUS",
        "REQUEST_SECURITY_STATUS",
        "TRIGGER_LOCAL_SECURITY_SCAN",
        "REFRESH_TELEMETRY",
    }

    def __init__(self, base_url: str, *, state_dir: Path | None = None, secret_store: SecretStore | None = None):
        self.base_url = base_url.rstrip("/")
        self.state_dir = state_dir or _state_dir()
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.device_id_path = self.state_dir / "device-id"
        self.secret_store = secret_store or default_secret_store(self.state_dir)
        self.stop_event = threading.Event()

    def device_id(self) -> str:
        if self.device_id_path.exists():
            value = self.device_id_path.read_text(encoding="utf-8").strip()
            if value:
                return value
        value = f"windows-{uuid.uuid4().hex}"
        temporary = self.device_id_path.with_suffix(".tmp")
        temporary.write_text(value, encoding="utf-8")
        os.replace(temporary, self.device_id_path)
        return value

    def token(self) -> str:
        token = self.secret_store.load()
        if not token:
            raise RuntimeError("Agent is not paired.")
        return token

    def _request(self, path: str, *, method: str = "GET", token: str = "", body: dict | None = None) -> dict:
        headers = {"Accept": "application/json"}
        if token:
            headers["X-Device-Token"] = token
            headers["X-Device-Id"] = self.device_id()
        data = None
        if body is not None:
            data = json.dumps(body, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = Request(f"{self.base_url}{path}", data=data, headers=headers, method=method)
        with urlopen(request, timeout=8) as response:
            return json.loads(response.read().decode("utf-8"))

    def pair(self, pairing_code: str, device_name: str | None = None) -> None:
        response = self._request(
            "/api/pairing/complete",
            method="POST",
            body={
                "pairing_code": pairing_code,
                "device_id": self.device_id(),
                "device_name": device_name or socket.gethostname(),
                "device_type": "computer",
                "platform": "windows",
                "agent_version": AGENT_VERSION,
                "os_info": {"system": platform.system(), "release": platform.release(), "version": platform.version()},
            },
        )
        token = response.get("device_token")
        if not token:
            raise RuntimeError("Pairing response did not include a device credential.")
        self.secret_store.save(token)
        logger.info("agent_paired", extra={"ccc_module": "agent", "metadata": {"device_id": self.device_id()}})

    def heartbeat(self) -> dict:
        return self._request(
            f"/api/managed-devices/{self.device_id()}/heartbeat",
            method="POST",
            token=self.token(),
            body={
                "heartbeat_id": uuid.uuid4().hex,
                "system_info": {"hostname": socket.gethostname(), "system": platform.system(), "release": platform.release(), "agent_version": AGENT_VERSION},
                "network_info": {"hostname": socket.gethostname()},
                "health": {"agent": "ok"},
            },
        )

    def send_telemetry(self, event_type: str, message: str, metadata: dict | None = None) -> dict:
        return self._request(
            f"/api/managed-devices/{self.device_id()}/telemetry",
            method="POST",
            token=self.token(),
            body={
                "telemetry_id": uuid.uuid4().hex,
                "event_type": event_type,
                "severity": "LOW",
                "message": message,
                "metadata": metadata or {},
            },
        )

    def _complete_action(self, action: dict) -> None:
        action_type = action.get("action_type")
        if action_type not in self.allowed_actions:
            status = "REJECTED"
            summary = "Rejected unknown action type."
        else:
            status = "COMPLETED"
            summary = f"Completed allowlisted read-only action {action_type}."
        self._request(
            f"/api/managed-devices/{self.device_id()}/actions/{action['action_id']}",
            method="PATCH",
            token=self.token(),
            body={"status": status, "result_summary": summary},
        )

    def run_once(self) -> dict:
        result = self.heartbeat()
        self.send_telemetry("AGENT_HEALTH", "Managed agent heartbeat completed.", {"agent_version": AGENT_VERSION})
        pending = self._request(f"/api/managed-devices/{self.device_id()}/actions/pending", token=self.token())
        for action in pending.get("items", []):
            self._complete_action(action)
        return result

    def run_forever(self, interval_seconds: int = 30) -> None:
        interval_seconds = max(10, min(interval_seconds, 300))
        backoff = 1
        logger.info("agent_started", extra={"ccc_module": "agent", "metadata": {"device_id": self.device_id()}})
        while not self.stop_event.is_set():
            try:
                self.run_once()
                backoff = 1
            except (OSError, RuntimeError, HTTPError, URLError, ValueError) as exc:
                logger.warning("agent_connection_failed", extra={"ccc_module": "agent", "metadata": {"reason": str(exc)[:160]}})
                self.stop_event.wait(backoff)
                backoff = min(backoff * 2, 60)
                continue
            self.stop_event.wait(interval_seconds)
        logger.info("agent_stopped", extra={"ccc_module": "agent"})

    def stop(self) -> None:
        self.stop_event.set()


def main() -> None:
    parser = argparse.ArgumentParser(description="Cyber Command Center defensive Windows agent")
    parser.add_argument("--url", default=os.getenv("CCC_AGENT_URL", "http://127.0.0.1:8001"))
    parser.add_argument("--pairing-code", default=os.getenv("CCC_AGENT_PAIRING_CODE"))
    parser.add_argument("--device-name", default=os.getenv("CCC_AGENT_DEVICE_NAME"))
    parser.add_argument("--interval", type=int, default=int(os.getenv("CCC_AGENT_INTERVAL_SECONDS", "30")))
    parser.add_argument(
        "--show-device-id",
        action="store_true",
        help="print this agent's non-secret device ID for identity-bound pairing, then exit",
    )
    args = parser.parse_args()
    logging.basicConfig(level=os.getenv("CCC_AGENT_LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(message)s")
    agent = WindowsAgent(args.url)
    if args.show_device_id:
        print(agent.device_id())
        return
    if args.pairing_code and not agent.secret_store.load():
        agent.pair(args.pairing_code, args.device_name)
    try:
        agent.run_forever(args.interval)
    except KeyboardInterrupt:
        agent.stop()


if __name__ == "__main__":
    main()
