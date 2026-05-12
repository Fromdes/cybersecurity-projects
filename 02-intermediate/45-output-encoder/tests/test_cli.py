"""CLI tests for Output Encoder."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from project_45.cli import main


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


class TestEncodeCmd:
    def test_html_body(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["encode", "<b>", "--context", "html_body"])
        assert result.exit_code == 0
        assert "&lt;b&gt;" in result.output

    def test_url_param(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["encode", "hello world", "--context", "url_param"])
        assert result.exit_code == 0
        assert "%20" in result.output

    def test_json_output(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["encode", "test", "--context", "html_body", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["context"] == "html_body"
        assert "output" in data

    def test_css_dangerous_rejected(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["encode", "expression(alert(1))", "--context", "css_value"])
        assert result.exit_code == 1
        assert "REJECTED" in result.output or "rejected" in result.output.lower()


class TestDemoCmd:
    def test_demo_runs(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["demo"])
        assert result.exit_code == 0
        assert "html_body" in result.output
        assert "REJECTED" in result.output  # CSS expression should be rejected


class TestCompareCmd:
    def test_compare_runs(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["compare", "<script>alert(1)</script>"])
        assert result.exit_code == 0
        assert "html_body" in result.output
        assert "js_string" in result.output
