"""Tests for project 61 auditd parser."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from project_61.core import (
    AuditAlert,
    AuditEvent,
    AuditRecord,
    correlate_records,
    detect_anomalies,
    parse_line,
    parse_log_file,
)

# Sample auditd log lines
LINE_SYSCALL = (
    'type=SYSCALL msg=audit(1700000001.123:100): arch=c000003e syscall=59 '
    'success=yes exit=0 a0=7f a1=7e a2=7d a3=7c items=2 ppid=1000 pid=1001 '
    'auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 '
    'tty=pts0 ses=1 comm="sudo" exe="/usr/bin/sudo" key="priv_esc"'
)
LINE_EXECVE = (
    'type=EXECVE msg=audit(1700000001.123:100): argc=3 a0="sudo" a1="-i" a2="bash"'
)
LINE_SETUID = (
    'type=SYSCALL msg=audit(1700000002.000:200): arch=c000003e syscall=105 '
    'success=yes exit=0 a0=0 items=0 ppid=500 pid=501 '
    'auid=1000 uid=1000 gid=1000 euid=1000 '
    'tty=pts0 ses=1 comm="evil" exe="/tmp/evil" key=""'
)


class TestParseLine:
    def test_parses_syscall_line(self) -> None:
        rec = parse_line(LINE_SYSCALL)
        assert rec is not None
        assert rec.record_type == "SYSCALL"
        assert rec.serial == 100
        assert abs(rec.timestamp - 1700000001.123) < 0.001

    def test_parses_fields(self) -> None:
        rec = parse_line(LINE_SYSCALL)
        assert rec is not None
        assert rec.fields.get("syscall") == "59"
        assert rec.comm == "sudo"

    def test_invalid_line_returns_none(self) -> None:
        assert parse_line("random log line") is None

    def test_execve_line(self) -> None:
        rec = parse_line(LINE_EXECVE)
        assert rec is not None
        assert rec.record_type == "EXECVE"


class TestCorrelateRecords:
    def test_groups_by_serial(self) -> None:
        r1 = parse_line(LINE_SYSCALL)
        r2 = parse_line(LINE_EXECVE)
        assert r1 and r2
        events = correlate_records([r1, r2])
        assert len(events) == 1
        assert len(events[0].records) == 2

    def test_different_serials_separate(self) -> None:
        r1 = parse_line(LINE_SYSCALL)
        r2 = parse_line(LINE_SETUID)
        assert r1 and r2
        events = correlate_records([r1, r2])
        assert len(events) == 2


class TestAuditRecord:
    def test_syscall_name_mapped(self) -> None:
        rec = parse_line(LINE_SYSCALL)
        assert rec is not None
        assert rec.syscall_name == "execve"

    def test_exe_field(self) -> None:
        rec = parse_line(LINE_SYSCALL)
        assert rec is not None
        assert "sudo" in rec.exe


class TestDetectAnomalies:
    def _events_from_lines(self, *lines: str) -> list[AuditEvent]:
        records = [parse_line(l) for l in lines if parse_line(l)]
        return correlate_records([r for r in records if r])

    def test_privilege_command_alert(self) -> None:
        events = self._events_from_lines(LINE_SYSCALL)
        alerts = detect_anomalies(events)
        assert any(a.reason == "privilege_command_exec" for a in alerts)

    def test_setuid_alert(self) -> None:
        events = self._events_from_lines(LINE_SETUID)
        alerts = detect_anomalies(events)
        assert any(a.reason == "setuid_call" or a.reason == "exec_from_tmp" for a in alerts)

    def test_exec_from_tmp_alert(self) -> None:
        events = self._events_from_lines(LINE_SETUID)
        alerts = detect_anomalies(events)
        assert any(a.reason == "exec_from_tmp" for a in alerts)

    def test_parse_log_file(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.log"
        log.write_text(LINE_SYSCALL + "\n" + LINE_EXECVE + "\n")
        events = parse_log_file(log)
        assert len(events) >= 1
