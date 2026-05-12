"""Tests for Office Macro Risk Analyzer CLI."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from project_80.cli import cli


class TestAnalyzeCommand:
    def test_analyze_basic(self, tmp_path: Path) -> None:
        f = tmp_path / "test.doc"
        f.write_bytes(b"Some text without macros " * 20)
        runner = CliRunner()
        result = runner.invoke(cli, ["analyze", str(f)])
        assert result.exit_code == 0
        assert "SHA256" in result.output
        assert "Risk score" in result.output

    def test_analyze_output_file(self, tmp_path: Path) -> None:
        f = tmp_path / "test.docm"
        f.write_bytes(b"Sub AutoOpen\nEnd Sub " * 5)
        out = tmp_path / "report.json"
        runner = CliRunner()
        result = runner.invoke(cli, ["analyze", str(f), "-o", str(out)])
        assert result.exit_code == 0
        assert out.exists()
        report = json.loads(out.read_text())
        assert "sha256" in report


class TestBatchCommand:
    def test_batch_empty_dir(self, tmp_path: Path) -> None:
        runner = CliRunner()
        out = tmp_path / "batch.json"
        result = runner.invoke(cli, ["batch", str(tmp_path), "-o", str(out)])
        assert result.exit_code == 0
