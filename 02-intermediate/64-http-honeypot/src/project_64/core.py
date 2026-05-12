"""HTTP honeypot: log all requests, detect scanners and exploit attempts."""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock
from typing import Any, Final

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Paths that attackers commonly probe
HONEYPOT_PATHS: Final[frozenset[str]] = frozenset({
    "/admin", "/wp-admin", "/wp-login.php", "/phpmyadmin",
    "/.env", "/.git/config", "/config.php", "/backup.zip",
    "/shell.php", "/c99.php", "/r57.php", "/cmd.php",
    "/actuator/env", "/actuator/health",
    "/login", "/administrator", "/setup.php",
})

# Patterns indicating exploit/scanner attempts
ATTACK_PATTERNS: Final[list[tuple[str, str]]] = [
    (r"\.\.\/", "path_traversal"),
    (r"<script", "xss_attempt"),
    (r"(?i)(select|union|insert|drop|update)\s+", "sql_injection"),
    (r"(?i)\$\{jndi:", "log4shell"),
    (r"/etc/passwd", "lfi_etc_passwd"),
    (r"(?i)(cmd|exec|system|passthru)\s*\(", "code_execution"),
    (r"(?i)wget|curl.*http", "download_attempt"),
    (r"(?i)(nmap|masscan|nikto|sqlmap|acunetix)", "scanner_ua"),
]

_COMPILED_PATTERNS: Final[list[tuple[re.Pattern[str], str]]] = [
    (re.compile(pat), name) for pat, name in ATTACK_PATTERNS
]


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class HTTPRequest:
    """Captured HTTP request."""

    timestamp: float
    src_ip: str
    src_port: int
    method: str
    path: str
    query_string: str
    http_version: str
    headers: dict[str, str]
    body: str
    session_id: str


@dataclass
class ThreatClassification:
    """Threat classification result for a request."""

    request: HTTPRequest
    is_threat: bool
    threat_types: list[str]
    severity: str  # "low" | "medium" | "high"
    is_honeypot_hit: bool


# ---------------------------------------------------------------------------
# Threat classifier
# ---------------------------------------------------------------------------

def classify_request(req: HTTPRequest) -> ThreatClassification:
    """Classify an HTTP request for threat indicators."""
    threat_types: list[str] = []
    full_text = f"{req.path}?{req.query_string} {req.body} {req.headers.get('User-Agent', '')}"

    for pattern, name in _COMPILED_PATTERNS:
        if pattern.search(full_text):
            threat_types.append(name)

    is_honeypot = req.path.rstrip("/") in HONEYPOT_PATHS or req.path in HONEYPOT_PATHS

    severity = "low"
    if any(t in threat_types for t in ("log4shell", "code_execution", "lfi_etc_passwd")):
        severity = "high"
    elif threat_types or is_honeypot:
        severity = "medium"

    return ThreatClassification(
        request=req,
        is_threat=bool(threat_types) or is_honeypot,
        threat_types=threat_types,
        severity=severity,
        is_honeypot_hit=is_honeypot,
    )


# ---------------------------------------------------------------------------
# Event store
# ---------------------------------------------------------------------------

@dataclass
class HTTPHoneypotLogger:
    """Thread-safe store for honeypot HTTP events."""

    log_path: Path | None = None
    _requests: list[ThreatClassification] = field(default_factory=list)
    _lock: Lock = field(default_factory=Lock)

    def record(self, tc: ThreatClassification) -> None:
        with self._lock:
            self._requests.append(tc)
        logger.info(
            "HTTP honeypot: %s %s from %s — threat=%s types=%s",
            tc.request.method, tc.request.path, tc.request.src_ip,
            tc.is_threat, tc.threat_types,
        )
        if self.log_path:
            self._write(tc)

    def _write(self, tc: ThreatClassification) -> None:
        entry = {
            "timestamp": tc.request.timestamp,
            "src_ip": tc.request.src_ip,
            "method": tc.request.method,
            "path": tc.request.path,
            "query": tc.request.query_string,
            "user_agent": tc.request.headers.get("User-Agent", ""),
            "is_threat": tc.is_threat,
            "threat_types": tc.threat_types,
            "severity": tc.severity,
            "honeypot_hit": tc.is_honeypot_hit,
        }
        assert self.log_path is not None
        with open(self.log_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")

    def all_events(self) -> list[ThreatClassification]:
        with self._lock:
            return list(self._requests)

    def threat_summary(self) -> dict[str, Any]:
        events = self.all_events()
        threats = [e for e in events if e.is_threat]
        type_counts: dict[str, int] = {}
        for e in threats:
            for t in e.threat_types:
                type_counts[t] = type_counts.get(t, 0) + 1
        ip_counts: dict[str, int] = {}
        for e in threats:
            ip_counts[e.request.src_ip] = ip_counts.get(e.request.src_ip, 0) + 1
        return {
            "total_requests": len(events),
            "threat_requests": len(threats),
            "type_counts": type_counts,
            "top_ips": sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10],
        }
