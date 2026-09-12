from __future__ import annotations

import hashlib
import re
import xml.etree.ElementTree as ET
import zipfile
from io import BytesIO
from pathlib import PurePath


ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.READ_CALL_LOG",
    "android.permission.SYSTEM_ALERT_WINDOW",
}


def safe_apk_filename(filename: str) -> str:
    name = PurePath(filename.replace("\\", "/")).name
    if not name or name in {".", ".."} or not name.lower().endswith(".apk"):
        raise ValueError("Upload must be an APK file.")
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)[:120]


def _strip_ns(name: str) -> str:
    return name.split("}", 1)[-1]


def _attr(element: ET.Element, name: str) -> str | None:
    return element.attrib.get(name) or element.attrib.get(f"{ANDROID_NS}{name}")


def _risk_level(score: int) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def _plain_manifest(data: bytes) -> ET.Element:
    return ET.fromstring(data.decode("utf-8", errors="ignore"))


def _binary_manifest_summary(data: bytes) -> dict:
    strings = {
        match.group(0).decode("utf-8", errors="ignore")
        for match in re.finditer(rb"[A-Za-z0-9_.$:/-]{4,}", data)
    }
    permissions = sorted(item for item in strings if item.startswith("android.permission."))
    package = next((item for item in strings if "." in item and not item.startswith("android.")), None)
    return {
        "package_name": package,
        "version_name": None,
        "version_code": None,
        "min_sdk": None,
        "target_sdk": None,
        "permissions": permissions,
        "activities": [],
        "services": [],
        "receivers": [],
        "providers": [],
        "exported_components": [],
        "debuggable": False,
        "allow_backup": None,
        "cleartext_traffic": None,
        "network_security_config": None,
        "binary_manifest_limited": True,
    }


def _parse_manifest(data: bytes) -> dict:
    try:
        root = _plain_manifest(data)
    except (ET.ParseError, UnicodeDecodeError):
        return _binary_manifest_summary(data)

    application = root.find("application")
    uses_sdk = root.find("uses-sdk")
    components = {"activity": [], "service": [], "receiver": [], "provider": []}
    exported: list[dict] = []
    if application is not None:
        for child in application:
            tag = _strip_ns(child.tag)
            if tag in components:
                name = _attr(child, "name") or "unknown"
                components[tag].append(name)
                if _attr(child, "exported") == "true":
                    exported.append({"type": tag, "name": name})

    return {
        "package_name": root.attrib.get("package"),
        "version_name": root.attrib.get(f"{ANDROID_NS}versionName") or root.attrib.get("versionName"),
        "version_code": root.attrib.get(f"{ANDROID_NS}versionCode") or root.attrib.get("versionCode"),
        "min_sdk": _attr(uses_sdk, "minSdkVersion") if uses_sdk is not None else None,
        "target_sdk": _attr(uses_sdk, "targetSdkVersion") if uses_sdk is not None else None,
        "permissions": sorted(
            _attr(item, "name") or ""
            for item in root.findall("uses-permission")
            if _attr(item, "name")
        ),
        "activities": components["activity"],
        "services": components["service"],
        "receivers": components["receiver"],
        "providers": components["provider"],
        "exported_components": exported,
        "debuggable": _attr(application, "debuggable") == "true" if application is not None else False,
        "allow_backup": _attr(application, "allowBackup") if application is not None else None,
        "cleartext_traffic": _attr(application, "usesCleartextTraffic") if application is not None else None,
        "network_security_config": _attr(application, "networkSecurityConfig") if application is not None else None,
        "binary_manifest_limited": False,
    }


def _certificate_info(names: list[str]) -> list[dict]:
    certs = [name for name in names if name.upper().startswith("META-INF/") and name.upper().endswith((".RSA", ".DSA", ".EC"))]
    return [{"file": cert} for cert in certs]


def _finding(title: str, severity: str, explanation: str, evidence: str, remediation: str) -> dict:
    return {
        "title": title,
        "severity": severity,
        "explanation": explanation,
        "evidence": evidence,
        "remediation": remediation,
    }


def analyze_apk(content: bytes, filename: str, max_size: int = 60 * 1024 * 1024) -> dict:
    clean_name = safe_apk_filename(filename)
    if len(content) > max_size:
        raise ValueError("APK upload is too large for the local lab limit.")
    digest = hashlib.sha256(content).hexdigest()
    try:
        with zipfile.ZipFile(BytesIO(content)) as archive:
            names = archive.namelist()
            if "AndroidManifest.xml" not in names:
                raise ValueError("APK does not contain AndroidManifest.xml.")
            manifest = _parse_manifest(archive.read("AndroidManifest.xml"))
            certificates = _certificate_info(names)
    except zipfile.BadZipFile as exc:
        raise ValueError("Malformed APK file.") from exc

    findings: list[dict] = []
    dangerous = [item for item in manifest["permissions"] if item in DANGEROUS_PERMISSIONS]
    for permission in dangerous:
        findings.append(
            _finding(
                "Dangerous permission requested",
                "MEDIUM",
                "The APK requests a permission Android treats as sensitive. This is not malware by itself, but it deserves review.",
                permission,
                "Confirm the permission is necessary and explain it clearly to users.",
            )
        )
    for component in manifest["exported_components"]:
        findings.append(
            _finding(
                "Exported component",
                "MEDIUM",
                "Exported Android components can be reached by other apps and should be intentionally designed.",
                f"{component['type']}: {component['name']}",
                "Set exported=false unless the component must be externally accessible.",
            )
        )
    if manifest["debuggable"]:
        findings.append(
            _finding(
                "Debuggable application",
                "HIGH",
                "Debuggable release builds expose extra runtime inspection and should not be shipped.",
                "android:debuggable=true",
                "Disable debugging for release builds.",
            )
        )
    if manifest["allow_backup"] == "true":
        findings.append(
            _finding(
                "Backup enabled",
                "LOW",
                "Application data may be included in device backups.",
                "android:allowBackup=true",
                "Disable backup for sensitive apps or configure backup rules.",
            )
        )
    if manifest["cleartext_traffic"] == "true":
        findings.append(
            _finding(
                "Cleartext traffic enabled",
                "HIGH",
                "The app explicitly allows unencrypted HTTP traffic.",
                "android:usesCleartextTraffic=true",
                "Require HTTPS and restrict cleartext traffic through network security config.",
            )
        )
    target_sdk = int(manifest["target_sdk"]) if str(manifest["target_sdk"] or "").isdigit() else None
    if target_sdk and target_sdk < 26:
        findings.append(
            _finding(
                "Old target SDK",
                "MEDIUM",
                "Older target SDKs miss newer Android platform protections.",
                f"targetSdkVersion={target_sdk}",
                "Update target SDK and retest behavior.",
            )
        )

    score = min(
        100,
        sum({"LOW": 8, "MEDIUM": 18, "HIGH": 34, "CRITICAL": 55}[item["severity"]] for item in findings),
    )
    return {
        "filename": clean_name,
        "sha256": digest,
        "package_name": manifest["package_name"],
        "version_name": manifest["version_name"],
        "version_code": manifest["version_code"],
        "min_sdk": manifest["min_sdk"],
        "target_sdk": manifest["target_sdk"],
        "permissions": manifest["permissions"],
        "activities": manifest["activities"],
        "services": manifest["services"],
        "receivers": manifest["receivers"],
        "providers": manifest["providers"],
        "exported_components": manifest["exported_components"],
        "debuggable": manifest["debuggable"],
        "allow_backup": manifest["allow_backup"],
        "cleartext_traffic": manifest["cleartext_traffic"],
        "network_security_config": manifest["network_security_config"],
        "certificates": certificates,
        "findings": findings,
        "risk_score": score,
        "risk_level": _risk_level(score),
        "manifest_limited": manifest["binary_manifest_limited"],
    }
