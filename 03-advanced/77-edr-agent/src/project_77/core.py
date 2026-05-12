"""Lightweight EDR Agent — process, network, and command-line anomaly detection."""

from __future__ import annotations

import hashlib
import json
import logging
import re
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

import psutil

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────────

SUSPICIOUS_COMMANDS: tuple[str, ...] = (
    "nc ", "netcat", "ncat",
    r"curl.+\|\s*sh\b", r"wget.+\|\s*sh\b",
    "python.*-c.*import", "perl.*-e",
    "base64 -d", "chmod.*777", "chmod.*+x.*tmp",
    "/tmp/", "/dev/shm/",
    "mkfifo", "mknod",
    "dd if=", "cat /etc/shadow", "cat /etc/passwd",
)

SUSPICIOUS_PORTS: frozenset[int] = frozenset({
    4444, 1337, 31337, 8888, 9001, 9002,
    6666, 12345, 54321,
})

PRIVILEGED_PROCESSES: tuple[str, ...] = (
    "sudo", "su", "pkexec", "doas",
)


class ThreatLevel(str, Enum):
    """EDR finding threat level."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# ── Finding dataclass ──────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Finding:
    """A suspicious activity finding from the EDR agent."""

    finding_id: str
    timestamp: datetime
    threat_level: ThreatLevel
    category: str
    description: str
    details: dict[str, Any] = field(default_factory=dict)
    mitre_technique: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "finding_id": self.finding_id,
            "timestamp": self.timestamp.isoformat(),
            "threat_level": self.threat_level.value,
            "category": self.category,
            "description": self.description,
            "mitre_technique": self.mitre_technique,
            "details": self.details,
        }

    @staticmethod
    def make_id(category: str, details: str) -> str:
        """Generate deterministic finding ID."""
        return hashlib.sha256(f"{category}{details}".encode()).hexdigest()[:12]


# ── Process snapshot ───────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ProcessSnapshot:
    """Snapshot of a running process."""

    pid: int
    ppid: int
    name: str
    exe: str
    cmdline: str
    username: str
    create_time: float
    connections: int


def snapshot_processes() -> list[ProcessSnapshot]:
    """Collect snapshots of all running processes."""
    snapshots: list[ProcessSnapshot] = []
    for proc in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline", "username", "create_time"]):
        try:
            info = proc.info
            cmdline = " ".join(info.get("cmdline") or [])
            try:
                conns = len(proc.net_connections())
            except (psutil.AccessDenied, AttributeError):
                conns = 0
            snapshots.append(ProcessSnapshot(
                pid=info["pid"] or 0,
                ppid=info["ppid"] or 0,
                name=info.get("name") or "",
                exe=info.get("exe") or "",
                cmdline=cmdline,
                username=info.get("username") or "",
                create_time=info.get("create_time") or 0.0,
                connections=conns,
            ))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return snapshots


# ── Detection functions ────────────────────────────────────────────────────────

def detect_suspicious_cmdline(snapshot: ProcessSnapshot) -> Finding | None:
    """Check process command line for suspicious patterns."""
    cmdline_lower = snapshot.cmdline.lower()
    for pattern in SUSPICIOUS_COMMANDS:
        if re.search(pattern, cmdline_lower):
            fid = Finding.make_id("suspicious_cmdline", f"{snapshot.pid}{pattern}")
            return Finding(
                finding_id=fid,
                timestamp=datetime.now(UTC),
                threat_level=ThreatLevel.HIGH,
                category="suspicious_cmdline",
                description=f"Suspicious command pattern '{pattern}' in PID {snapshot.pid}",
                details={"pid": snapshot.pid, "cmdline": snapshot.cmdline[:200], "pattern": pattern},
                mitre_technique="T1059",
            )
    return None


def detect_privileged_execution(snapshot: ProcessSnapshot) -> Finding | None:
    """Alert when privileged escalation tools are executed."""
    if snapshot.name in PRIVILEGED_PROCESSES:
        fid = Finding.make_id("privilege_exec", f"{snapshot.pid}{snapshot.name}")
        return Finding(
            finding_id=fid,
            timestamp=datetime.now(UTC),
            threat_level=ThreatLevel.MEDIUM,
            category="privilege_execution",
            description=f"Privileged process '{snapshot.name}' running (PID {snapshot.pid})",
            details={"pid": snapshot.pid, "name": snapshot.name, "user": snapshot.username},
            mitre_technique="T1548.003",
        )
    return None


def detect_suspicious_connections(snapshot: ProcessSnapshot) -> Finding | None:
    """Check for processes with unusual numbers of network connections."""
    if snapshot.connections > 50:
        fid = Finding.make_id("conn_flood", f"{snapshot.pid}{snapshot.connections}")
        return Finding(
            finding_id=fid,
            timestamp=datetime.now(UTC),
            threat_level=ThreatLevel.MEDIUM,
            category="connection_flood",
            description=f"PID {snapshot.pid} ({snapshot.name}) has {snapshot.connections} connections",
            details={"pid": snapshot.pid, "name": snapshot.name, "connections": snapshot.connections},
            mitre_technique="T1071",
        )
    return None


def detect_suspicious_listening_ports() -> list[Finding]:
    """Detect processes listening on known suspicious ports."""
    findings: list[Finding] = []
    for conn in psutil.net_connections(kind="inet"):
        try:
            if conn.status == "LISTEN" and conn.laddr.port in SUSPICIOUS_PORTS:
                fid = Finding.make_id("suspicious_port", str(conn.laddr.port))
                findings.append(Finding(
                    finding_id=fid,
                    timestamp=datetime.now(UTC),
                    threat_level=ThreatLevel.HIGH,
                    category="suspicious_port",
                    description=f"Process listening on suspicious port {conn.laddr.port}",
                    details={"port": conn.laddr.port, "pid": conn.pid},
                    mitre_technique="T1049",
                ))
        except (AttributeError, TypeError):
            continue
    return findings


def detect_hidden_processes(snapshots: list[ProcessSnapshot]) -> list[Finding]:
    """Detect processes without executable path (possible injection)."""
    findings: list[Finding] = []
    for snap in snapshots:
        if snap.pid > 1 and not snap.exe and snap.name not in ("kworker", "kthread"):
            fid = Finding.make_id("hidden_proc", str(snap.pid))
            findings.append(Finding(
                finding_id=fid,
                timestamp=datetime.now(UTC),
                threat_level=ThreatLevel.HIGH,
                category="hidden_process",
                description=f"Process PID {snap.pid} ({snap.name}) has no executable path",
                details={"pid": snap.pid, "name": snap.name, "cmdline": snap.cmdline[:100]},
                mitre_technique="T1055",
            ))
    return findings


# ── EDR Agent ─────────────────────────────────────────────────────────────────

class EDRAgent:
    """Orchestrates all EDR detection checks."""

    def __init__(self, output_path: Path | None = None) -> None:
        self._output_path = output_path
        self._findings: list[Finding] = []
        self._lock = threading.Lock()

    def _record(self, finding: Finding) -> None:
        with self._lock:
            self._findings.append(finding)
        if self._output_path:
            with self._output_path.open("a") as fh:
                fh.write(json.dumps(finding.to_dict()) + "\n")
        logger.warning("[%s] %s — %s", finding.threat_level.value, finding.category, finding.description)

    def scan_once(self) -> list[Finding]:
        """Run a single full scan and return new findings."""
        batch: list[Finding] = []
        snapshots = snapshot_processes()

        for snap in snapshots:
            for fn in (detect_suspicious_cmdline, detect_privileged_execution, detect_suspicious_connections):
                finding = fn(snap)
                if finding:
                    self._record(finding)
                    batch.append(finding)

        for finding in detect_suspicious_listening_ports():
            self._record(finding)
            batch.append(finding)

        for finding in detect_hidden_processes(snapshots):
            self._record(finding)
            batch.append(finding)

        return batch

    def run_continuous(self, interval: float, stop_event: threading.Event) -> None:
        """Run scans continuously until stop_event is set."""
        while not stop_event.is_set():
            self.scan_once()
            stop_event.wait(interval)

    def get_findings(self) -> list[Finding]:
        """Return a snapshot of all recorded findings."""
        with self._lock:
            return list(self._findings)

    def summary(self) -> dict[str, int]:
        """Return finding counts by threat level."""
        counts = {lvl.value: 0 for lvl in ThreatLevel}
        with self._lock:
            for f in self._findings:
                counts[f.threat_level.value] += 1
        return counts
