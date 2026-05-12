"""Tests for Dependency Vulnerability Checker CLI."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch, MagicMock

from click.testing import CliRunner

from project_85.cli import cli
from project_85.core import Dependency, DependencyResult, Vulnerability


class TestCheckCommand:
    def test_check_offline(self, tmp_path: Path) -> None:
        f = tmp_path / "requirements.txt"
        f.write_text("requests==2.28.0\n")
        runner = CliRunner()
        result = runner.invoke(cli, ["check", str(f), "--offline"])
        assert result.exit_code == 0
        assert "offline" in result.output.lower()

    def test_check_with_mocked_results(self, tmp_path: Path) -> None:
        f = tmp_path / "requirements.txt"
        f.write_text("requests==2.0.0\n")
        dep = Dependency("requests", "2.0.0", "PyPI")
        vuln = Vulnerability("PYSEC-001", "Test vuln", "HIGH", 7.5, "2.28.0", [])
        dr = DependencyResult(dependency=dep, vulnerabilities=[vuln])
        runner = CliRunner()
        with patch("project_85.cli.query_osv_batch", return_value=[dr]):
            result = runner.invoke(cli, ["check", str(f)])
        assert result.exit_code == 0
        assert "PYSEC-001" in result.output

    def test_check_exit_code_on_vuln(self, tmp_path: Path) -> None:
        f = tmp_path / "requirements.txt"
        f.write_text("requests==2.0.0\n")
        dep = Dependency("requests", "2.0.0", "PyPI")
        vuln = Vulnerability("PYSEC-001", "Test", "HIGH", 7.5, "2.28.0")
        dr = DependencyResult(dependency=dep, vulnerabilities=[vuln])
        runner = CliRunner()
        with patch("project_85.cli.query_osv_batch", return_value=[dr]):
            result = runner.invoke(cli, ["check", str(f), "--exit-code"])
        assert result.exit_code == 1

    def test_check_output_file(self, tmp_path: Path) -> None:
        f = tmp_path / "requirements.txt"
        f.write_text("requests==2.28.0\n")
        out = tmp_path / "report.json"
        runner = CliRunner()
        with patch("project_85.cli.query_osv_batch", return_value=[
            DependencyResult(dependency=Dependency("requests", "2.28.0", "PyPI"), vulnerabilities=[])
        ]):
            result = runner.invoke(cli, ["check", str(f), "-o", str(out)])
        assert result.exit_code == 0
        assert out.exists()
        report = json.loads(out.read_text())
        assert "total_dependencies" in report


class TestQueryCommand:
    def test_query_no_vulns(self) -> None:
        dep = Dependency("safe", "1.0.0", "PyPI")
        dr = DependencyResult(dependency=dep, vulnerabilities=[])
        runner = CliRunner()
        with patch("project_85.cli.query_osv_single", return_value=dr):
            result = runner.invoke(cli, ["query", "safe", "1.0.0"])
        assert result.exit_code == 0
        assert "No known vulnerabilities" in result.output
