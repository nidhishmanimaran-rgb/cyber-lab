from __future__ import annotations

import ipaddress
import platform
import re
import socket
import subprocess
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.core.config import Settings
from backend.core.logging import get_logger
from backend.detection.engine import create_event
from backend.models import Device


PRIVATE_FALLBACK = ipaddress.ip_network("192.168.0.0/16")
COMMON_SERVICE_PORTS = {
    22: "ssh",
    53: "dns",
    80: "http",
    443: "https",
    445: "smb",
    8000: "http-alt",
    8001: "ccc-api",
}

logger = get_logger("backend.network")


def validate_network_scope(cidr: str, settings: Settings) -> ipaddress.IPv4Network:
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise ValueError("Invalid CIDR network.") from exc
    if network.version != 4:
        raise ValueError("Only IPv4 local lab monitoring is supported.")
    authorized = [ipaddress.ip_network(item, strict=False) for item in settings.authorized_network_ranges]
    if network.is_loopback or network.is_private:
        return network
    if any(network.subnet_of(item) or network == item for item in authorized):
        return network
    raise ValueError("Network scope must be private, loopback, or explicitly authorized.")


def detect_local_networks(settings: Settings) -> list[str]:
    networks: set[str] = set(settings.authorized_network_ranges)
    try:
        hostname = socket.gethostname()
        for ip in socket.gethostbyname_ex(hostname)[2]:
            address = ipaddress.ip_address(ip)
            if address.version == 4 and (address.is_private or address.is_loopback):
                prefix = 8 if address.is_loopback else 24
                networks.add(str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False)))
    except OSError:
        pass
    if not networks:
        networks.add(str(PRIVATE_FALLBACK))
    return sorted(networks)


def _ping(ip: str) -> bool:
    count_arg = "-n" if platform.system().lower() == "windows" else "-c"
    timeout_arg = "-w" if platform.system().lower() == "windows" else "-W"
    command = ["ping", count_arg, "1", timeout_arg, "750", ip]
    try:
        return subprocess.run(
            command,
            capture_output=True,
            check=False,
            timeout=2,
        ).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _arp_table() -> dict[str, str]:
    try:
        result = subprocess.run(
            ["arp", "-a"],
            capture_output=True,
            check=False,
            text=True,
            timeout=3,
        )
    except (OSError, subprocess.SubprocessError):
        return {}
    entries: dict[str, str] = {}
    pattern = re.compile(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:-]{11,17})")
    for match in pattern.finditer(result.stdout):
        entries[match.group(1)] = match.group(2).replace("-", ":").upper()
    return entries


def _hostname(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return None


def _service_checks(ip: str) -> list[dict]:
    services = []
    for port, name in COMMON_SERVICE_PORTS.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.18)
        try:
            if sock.connect_ex((ip, port)) == 0:
                services.append({"port": port, "name": name})
        except OSError:
            pass
        finally:
            sock.close()
    return services


def discover_devices(cidr: str, settings: Settings) -> list[dict]:
    network = validate_network_scope(cidr, settings)
    hosts = list(network.hosts())[: settings.network_scan_max_hosts]
    for host in hosts:
        _ping(str(host))
    arp = _arp_table()
    devices = []
    for host in hosts:
        ip = str(host)
        if ip in arp or ip == "127.0.0.1":
            devices.append(
                {
                    "ip_address": ip,
                    "mac_address": arp.get(ip),
                    "hostname": _hostname(ip),
                    "vendor": "Unknown",
                    "status": "online",
                    "services": _service_checks(ip),
                }
            )
    return devices


def record_scan(db: Session, discovered: list[dict]) -> dict:
    now = datetime.now(timezone.utc)
    seen_ips = {item["ip_address"] for item in discovered}
    created = 0
    updated = 0
    events = 0

    for item in discovered:
        try:
            device = db.scalar(select(Device).where(Device.ip_address == item["ip_address"]))
            if device is None:
                device = Device(**item, first_seen=now, last_seen=now, known=False)
                db.add(device)
                db.commit()
                db.refresh(device)
                created += 1
                create_event(
                    db,
                    event_type="NEW_DEVICE",
                    severity="MEDIUM",
                    source="network",
                    message=f"New device detected. IP: {device.ip_address}. Hostname: {device.hostname or 'Unknown'}.",
                    metadata={"device_id": device.id, "ip_address": device.ip_address},
                )
                events += 1
                logger.info(
                    "device_discovered",
                    extra={
                        "ccc_module": "network",
                        "metadata": {"ip_address": device.ip_address, "hostname": device.hostname, "known": device.known},
                    },
                )
            else:
                was_offline = device.status == "offline"
                device.mac_address = item.get("mac_address") or device.mac_address
                device.hostname = item.get("hostname") or device.hostname
                device.vendor = item.get("vendor") or device.vendor
                device.services = item.get("services") or []
                device.status = "online"
                device.last_seen = now
                db.commit()
                updated += 1
                if was_offline:
                    create_event(
                        db,
                        event_type="DEVICE_ONLINE",
                        severity="LOW",
                        source="network",
                        message=f"Device back online. IP: {device.ip_address}.",
                        metadata={"device_id": device.id, "ip_address": device.ip_address},
                    )
        except Exception:
            db.rollback()
            logger.exception(
                "device_scan_item_failed",
                extra={"ccc_module": "network", "metadata": {"ip_address": item.get("ip_address")}},
            )
            continue

    offline_cutoff = now - timedelta(seconds=1)
    known_devices = db.scalars(select(Device)).all()
    for device in known_devices:
        try:
            if device.ip_address not in seen_ips and device.status == "online" and device.last_seen < offline_cutoff:
                device.status = "offline"
                db.commit()
                create_event(
                    db,
                    event_type="DEVICE_OFFLINE",
                    severity="LOW",
                    source="network",
                    message=f"Device appears offline. IP: {device.ip_address}.",
                    metadata={"device_id": device.id, "ip_address": device.ip_address},
                )
                events += 1
        except Exception:
            db.rollback()
            logger.exception(
                "offline_transition_failed",
                extra={"ccc_module": "network", "metadata": {"ip_address": device.ip_address}},
            )
            continue

    return {"created": created, "updated": updated, "events": events, "seen": len(discovered)}
