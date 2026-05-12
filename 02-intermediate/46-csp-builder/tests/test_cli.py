"""CLI tests for project 46."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from click.testing import CliRunner

from project_46.cli import cli


class TestBuildCommand:
    def test_strict_flag(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["build", "--strict"])
        assert result.exit_code == 0
        assert "default-src" in result.output

    def test_analyse_flag_with_unsafe(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli, ["build", "--add", "script-src='unsafe-inline'", "--analyse"]
        )
        assert result.exit_code == 0

    def test_invalid_add_format(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["build", "--add", "badformat"])
        assert result.exit_code == 1


class TestAnalyseCommand:
    def test_clean_policy(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["analyse", "default-src 'none'; object-src 'none'"])
        assert result.exit_code == 0

    def test_unsafe_policy(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["analyse", "script-src 'unsafe-inline'"])
        assert result.exit_code == 0
        assert "HIGH" in result.output


class TestParseReportCommand:
    def test_parse_valid_report(self) -> None:
        data = {
            "csp-report": {
                "document-uri": "https://example.com",
                "violated-directive": "script-src",
                "effective-directive": "script-src",
                "blocked-uri": "https://evil.com/x.js",
                "original-policy": "script-src 'self'",
            }
        }
        runner = CliRunner()
        with tempfile.NamedTemporaryFile(
            suffix=".json", mode="w", delete=False
        ) as f:
            json.dump(data, f)
            tmp_path = f.name
        result = runner.invoke(cli, ["parse-report", tmp_path])
        assert result.exit_code == 0
        assert "evil.com" in result.output
