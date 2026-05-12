"""Tests for Memory Dump IOC Extractor CLI."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from project_82.cli import cli


class TestExtractCommand:
    def test_extract_basic(self, tmp_path: Path) -> None:
        f = tmp_path / "dump.bin"
        f.write_bytes(b"Server 8.8.8.8 received request from http://evil.com/cmd " * 5)
        runner = CliRunner()
        result = runner.invoke(cli, ["extract", str(f)])
        assert result.exit_code == 0
        assert "SHA256" in result.output

    def test_extract_output_file(self, tmp_path: Path) -> None:
        f = tmp_path / "dump.bin"
        f.write_bytes(b"Contact attacker@evil.com for details " * 5)
        out = tmp_path / "report.json"
        runner = CliRunner()
        result = runner.invoke(cli, ["extract", str(f), "-o", str(out)])
        assert result.exit_code == 0
        assert out.exists()
        report = json.loads(out.read_text())
        assert "sha256" in report


class TestScanTextCommand:
    def test_scan_text(self, tmp_path: Path) -> None:
        f = tmp_path / "log.txt"
        f.write_text("2024-01-01 C2 at 1.2.3.4 — connecting to http://malware.com/update")
        runner = CliRunner()
        result = runner.invoke(cli, ["scan-text", str(f)])
        assert result.exit_code == 0
