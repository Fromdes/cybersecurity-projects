"""Tests for Lightweight EDR Agent CLI."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from project_77.cli import cli
from project_77.core import Finding, ThreatLevel
from datetime import datetime, timezone


def make_finding(level: ThreatLevel = ThreatLevel.HIGH) -> Finding:
    return Finding(
        finding_id="abc",
        timestamp=datetime.now(timezone.utc),
        threat_level=level,
        category="test",
        description="test finding",
    )


class TestScanCommand:
    def test_scan_runs(self) -> None:
        runner = CliRunner()
        with patch("project_77.core.snapshot_processes", return_value=[]):
            with patch("project_77.core.detect_suspicious_listening_ports", return_value=[]):
                result = runner.invoke(cli, ["scan"])
        assert result.exit_code == 0
        assert "Scan complete" in result.output

    def test_scan_with_finding(self) -> None:
        runner = CliRunner()
        finding = make_finding()
        with patch("project_77.core.EDRAgent.scan_once", return_value=[finding]):
            result = runner.invoke(cli, ["scan", "--min-level", "LOW"])
        assert result.exit_code == 0


class TestReportCommand:
    def test_report_output(self, tmp_path: Path) -> None:
        findings_file = tmp_path / "findings.jsonl"
        records = [
            {"finding_id": "1", "threat_level": "HIGH", "category": "c", "description": "d",
             "timestamp": datetime.now(timezone.utc).isoformat(), "mitre_technique": "", "details": {}},
            {"finding_id": "2", "threat_level": "MEDIUM", "category": "c", "description": "d",
             "timestamp": datetime.now(timezone.utc).isoformat(), "mitre_technique": "", "details": {}},
        ]
        findings_file.write_text("\n".join(json.dumps(r) for r in records) + "\n")
        runner = CliRunner()
        result = runner.invoke(cli, ["report", str(findings_file)])
        assert result.exit_code == 0
        assert "Total findings: 2" in result.output
        assert "HIGH: 1" in result.output
