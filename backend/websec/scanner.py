from __future__ import annotations

import ipaddress
import socket
import urllib.error
import urllib.parse
import urllib.request

from backend.core.config import Settings


SECURITY_HEADERS = {
    "content-security-policy": "Content-Security-Policy",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
    "referrer-policy": "Referrer-Policy",
}


def _is_private_host(hostname: str) -> bool:
    if hostname in {"localhost"}:
        return True
    try:
        ip = ipaddress.ip_address(hostname)
        return ip.is_private or ip.is_loopback
    except ValueError:
        pass
    try:
        resolved = {
            ipaddress.ip_address(result[4][0])
            for result in socket.getaddrinfo(hostname, None)
        }
    except OSError:
        return False
    return bool(resolved) and all(ip.is_private or ip.is_loopback for ip in resolved)


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def validate_target(target: str, settings: Settings) -> str:
    parsed = urllib.parse.urlparse(target)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Target must be an http or https URL.")
    if parsed.username or parsed.password:
        raise ValueError("Target URL must not contain credentials.")
    normalized = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", "", ""))
    allowed = {item.rstrip("/") for item in settings.authorized_scan_targets}
    if normalized.rstrip("/") in allowed or f"{parsed.scheme}://{parsed.netloc}" in allowed:
        return normalized
    if _is_private_host(parsed.hostname or ""):
        return normalized
    raise ValueError("WebSec target must be localhost, private, or explicitly authorized.")


def _finding(title: str, severity: str, evidence: str, explanation: str, remediation: str) -> dict:
    return {
        "title": title,
        "severity": severity,
        "evidence": evidence,
        "explanation": explanation,
        "remediation": remediation,
    }


def risk_level(score: int) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def scan_target(target: str, settings: Settings) -> dict:
    normalized = validate_target(target, settings)
    request = urllib.request.Request(normalized, headers={"User-Agent": "CyberCommandCenter-WebSec/1.0"})
    opener = urllib.request.build_opener(NoRedirectHandler)
    try:
        with opener.open(request, timeout=5) as response:
            headers = {key.lower(): value for key, value in response.headers.items()}
            status_code = response.status
            body = response.read(65536).decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as exc:
        if 300 <= exc.code < 400:
            raise ValueError("Redirects are not followed by the WebSec scanner.") from exc
        raise ValueError(f"Target returned HTTP {exc.code}.") from exc
    except urllib.error.URLError as exc:
        raise ValueError(f"Target request failed: {exc.reason}") from exc

    findings: list[dict] = []
    for header_key, header_name in SECURITY_HEADERS.items():
        if header_key not in headers:
            findings.append(
                _finding(
                    f"Missing {header_name}",
                    "MEDIUM" if header_key == "content-security-policy" else "LOW",
                    f"{header_name} header absent",
                    "Security headers help browsers enforce defensive behavior.",
                    f"Configure the application to send {header_name}.",
                )
            )
    cookie_headers = [value for key, value in headers.items() if key == "set-cookie"]
    for cookie in cookie_headers:
        lower = cookie.lower()
        if "httponly" not in lower:
            findings.append(_finding("Cookie missing HttpOnly", "MEDIUM", cookie, "HttpOnly reduces script access to cookies.", "Add the HttpOnly attribute."))
        if "samesite" not in lower:
            findings.append(_finding("Cookie missing SameSite", "LOW", cookie, "SameSite helps reduce cross-site request risks.", "Add SameSite=Lax or SameSite=Strict."))
        if normalized.startswith("https://") and "secure" not in lower:
            findings.append(_finding("HTTPS cookie missing Secure", "MEDIUM", cookie, "Secure keeps cookies on HTTPS transport.", "Add the Secure attribute."))
    if "trace enabled" in body.lower():
        findings.append(_finding("Unsafe configuration hint", "HIGH", "Response mentions TRACE enabled", "TRACE should not be exposed in most apps.", "Disable TRACE or similar debug behaviors."))

    score = min(100, sum({"LOW": 7, "MEDIUM": 16, "HIGH": 32, "CRITICAL": 55}[item["severity"]] for item in findings))
    highest = "LOW"
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if any(item["severity"] == level for item in findings):
            highest = level
            break
    return {
        "target": normalized,
        "status_code": status_code,
        "findings": findings,
        "risk_score": score,
        "risk_level": risk_level(score),
        "highest_severity": highest,
    }
