"""Tests for Dockerfile Linter CLI."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from project_87.cli import cli


def write_dockerfile(tmp_path: Path, content: str) -> Path:
    f = tmp_path / "Dockerfile"
    f.write_text(content)
    return f


class TestLintCommand:
    def test_lint_secure(self, tmp_path: Path) -> None:
        f = write_dockerfile(tmp_path, "FROM ubuntu:22.04\nUSER app\nHEALTHCHECK CMD true\n")
        runner = CliRunner()
        result = runner.invoke(cli, ["lint", str(f)])
        assert result.exit_code == 0

    def test_lint_insecure(self, tmp_path: Path) -> None:
        f = write_dockerfile(tmp_path, "FROM ubuntu:latest\nENV SECRET=abc\n")
        runner = CliRunner()
        result = runner.invoke(cli, ["lint", str(f)])
        assert result.exit_code == 0
        assert "CRITICAL" in result.output or "WARN" in result.output

    def test_exit_code_on_critical(self, tmp_path: Path) -> None:
        f = write_dockerfile(tmp_path, "FROM ubuntu:latest\n")
        runner = CliRunner()
        result = runner.invoke(cli, ["lint", str(f), "--exit-code"])
        assert result.exit_code == 1

    def test_output_file(self, tmp_path: Path) -> None:
        f = write_dockerfile(tmp_path, "FROM ubuntu:22.04\nUSER app\n")
        out = tmp_path / "report.json"
        runner = CliRunner()
        result = runner.invoke(cli, ["lint", str(f), "-o", str(out)])
        assert result.exit_code == 0
        assert out.exists()
        report = json.loads(out.read_text())
        assert "findings" in report
