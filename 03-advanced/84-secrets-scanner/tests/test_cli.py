"""Tests for Secrets Scanner CLI."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from project_84.cli import cli


class TestScanCommand:
    def test_scan_file(self, tmp_path: Path) -> None:
        f = tmp_path / "secrets.py"
        f.write_text('db_password = "MyStr0ngRealPassw0rd!"\n')
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", str(f)])
        assert result.exit_code == 0

    def test_scan_clean_file(self, tmp_path: Path) -> None:
        f = tmp_path / "clean.py"
        f.write_text("def add(a, b): return a + b\n")
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", str(f)])
        assert result.exit_code == 0
        assert "0 finding" in result.output

    def test_scan_directory(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text("print('hello')\n")
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", str(tmp_path)])
        assert result.exit_code == 0

    def test_exit_code_on_findings(self, tmp_path: Path) -> None:
        f = tmp_path / "secrets.pem"
        f.write_text("-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n")
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", str(f), "--exit-code"])
        assert result.exit_code == 1

    def test_output_file(self, tmp_path: Path) -> None:
        f = tmp_path / "secrets.pem"
        f.write_text("-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n")
        out = tmp_path / "findings.json"
        runner = CliRunner()
        runner.invoke(cli, ["scan", str(f), "-o", str(out)])
        assert out.exists()
        findings = json.loads(out.read_text())
        assert isinstance(findings, list)


class TestRulesCommand:
    def test_rules_output(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["rules"])
        assert result.exit_code == 0
        assert "AWS_ACCESS_KEY" in result.output
        assert "CRITICAL" in result.output
