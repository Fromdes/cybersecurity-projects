"""Parse Linux auditd log records into structured events."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_KV_RE: Final[re.Pattern[str]] = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)')
_HEADER_RE: Final[re.Pattern[str]] = re.compile(
    r"type=(\S+)\s+msg=audit\((\d+\.\d+):(\d+)\):"
)

# Syscall numbers of interest (Linux x86-64 common subset)
INTERESTING_SYSCALLS: Final[dict[str, str]] = {
    "59": "execve", "322": "execveat",
    "2": "open", "257": "openat",
    "87": "unlink", "263": "unlinkat",
    "105": "setuid", "117": "setresuid",
    "161": "chroot",
    "56": "clone",
}

PRIVILEGE_COMMANDS: Final[frozenset[str]] = frozenset({
    "su", "sudo", "passwd", "chown", "chmod", "chattr",
    "visudo", "adduser", "usermod", "deluser",
})


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class AuditRecord:
    """A single parsed auditd record."""

    record_type: str
    timestamp: float
    serial: int
    fields: dict[str, str] = field(default_factory=dict)

    @property
    def syscall_name(self) -> str:
        sc = self.fields.get("syscall", "")
        return INTERESTING_SYSCALLS.get(sc, sc)

    @property
    def exe(self) -> str:
        raw = self.fields.get("exe", "").strip('"')
        return raw

    @property
    def uid(self) -> str:
        return self.fields.get("uid", "")

    @property
    def auid(self) -> str:
        return self.fields.get("auid", "")

    @property
    def comm(self) -> str:
        return self.fields.get("comm", "").strip('"')

    @property
    def key(self) -> str:
        return self.fields.get("key", "").strip('"')


@dataclass
class AuditEvent:
    """Correlated multi-record audit event (same serial number)."""

    serial: int
    timestamp: float
    records: list[AuditRecord] = field(default_factory=list)

    @property
    def syscall_record(self) -> AuditRecord | None:
        for r in self.records:
            if r.record_type == "SYSCALL":
                return r
        return None

    @property
    def execve_record(self) -> AuditRecord | None:
        for r in self.records:
            if r.record_type == "EXECVE":
                return r
        return None

    def summary(self) -> str:
        sc = self.syscall_record
        if sc:
            return (
                f"ts={self.timestamp:.3f} serial={self.serial} "
                f"syscall={sc.syscall_name} exe={sc.exe} uid={sc.uid} comm={sc.comm}"
            )
        return f"ts={self.timestamp:.3f} serial={self.serial} records={len(self.records)}"


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def parse_line(line: str) -> AuditRecord | None:
    """Parse a single auditd log line into an AuditRecord."""
    m = _HEADER_RE.search(line)
    if not m:
        return None

    record_type = m.group(1)
    timestamp = float(m.group(2))
    serial = int(m.group(3))

    rest = line[m.end():]
    fields = {k: v.strip('"') for k, v in _KV_RE.findall(rest)}

    return AuditRecord(
        record_type=record_type,
        timestamp=timestamp,
        serial=serial,
        fields=fields,
    )


def correlate_records(records: list[AuditRecord]) -> list[AuditEvent]:
    """Group records by serial number into correlated AuditEvents."""
    by_serial: dict[int, AuditEvent] = {}
    for rec in records:
        if rec.serial not in by_serial:
            by_serial[rec.serial] = AuditEvent(serial=rec.serial, timestamp=rec.timestamp)
        by_serial[rec.serial].records.append(rec)
    return sorted(by_serial.values(), key=lambda e: e.timestamp)


def parse_log_file(path: Path) -> list[AuditEvent]:
    """Parse an auditd log file into correlated AuditEvents."""
    records: list[AuditRecord] = []
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            rec = parse_line(line)
            if rec:
                records.append(rec)
    return correlate_records(records)


# ---------------------------------------------------------------------------
# Anomaly detector
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AuditAlert:
    serial: int
    severity: str
    reason: str
    detail: str


def detect_anomalies(events: list[AuditEvent]) -> list[AuditAlert]:
    """Detect suspicious patterns in correlated audit events."""
    alerts: list[AuditAlert] = []

    for event in events:
        sc = event.syscall_record
        if not sc:
            continue

        # execve of privilege commands
        if sc.syscall_name in ("execve", "execveat"):
            comm = sc.comm.lower()
            if comm in PRIVILEGE_COMMANDS:
                alerts.append(AuditAlert(
                    serial=event.serial,
                    severity="medium",
                    reason="privilege_command_exec",
                    detail=f"{comm} executed by uid={sc.uid}",
                ))

        # setuid / setresuid calls
        if sc.syscall_name in ("setuid", "setresuid"):
            alerts.append(AuditAlert(
                serial=event.serial,
                severity="high",
                reason="setuid_call",
                detail=f"setuid called by uid={sc.uid} comm={sc.comm}",
            ))

        # chroot call
        if sc.syscall_name == "chroot":
            alerts.append(AuditAlert(
                serial=event.serial,
                severity="high",
                reason="chroot_call",
                detail=f"chroot called by uid={sc.uid}",
            ))

        # Execution from /tmp
        if sc.exe.startswith("/tmp/") or sc.exe.startswith("/dev/shm/"):
            alerts.append(AuditAlert(
                serial=event.serial,
                severity="high",
                reason="exec_from_tmp",
                detail=f"exe={sc.exe} uid={sc.uid}",
            ))

    return alerts
