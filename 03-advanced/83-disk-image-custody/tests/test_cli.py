"""Tests for Disk Image Hash & Chain-of-Custody CLI."""

from __future__ import annotations

import json
import hashlib
from pathlib import Path

from click.testing import CliRunner

from project_83.cli import cli


class TestHashCommand:
    def test_hash_output(self, tmp_path: Path) -> None:
        f = tmp_path / "image.dd"
        f.write_bytes(b"forensic test data")
        runner = CliRunner()
        result = runner.invoke(cli, ["hash", str(f)])
        assert result.exit_code == 0
        assert "SHA256" in result.output
        assert "MD5" in result.output

    def test_hash_to_file(self, tmp_path: Path) -> None:
        f = tmp_path / "image.dd"
        f.write_bytes(b"data")
        out = tmp_path / "hashes.json"
        runner = CliRunner()
        result = runner.invoke(cli, ["hash", str(f), "-o", str(out)])
        assert result.exit_code == 0
        assert out.exists()
        report = json.loads(out.read_text())
        assert "sha256" in report


class TestVerifyCommand:
    def test_verify_pass(self, tmp_path: Path) -> None:
        content = b"test image"
        f = tmp_path / "image.dd"
        f.write_bytes(content)
        expected = hashlib.sha256(content).hexdigest()
        runner = CliRunner()
        result = runner.invoke(cli, ["verify", str(f), expected])
        assert result.exit_code == 0
        assert "PASS" in result.output

    def test_verify_fail(self, tmp_path: Path) -> None:
        f = tmp_path / "image.dd"
        f.write_bytes(b"test")
        runner = CliRunner()
        result = runner.invoke(cli, ["verify", str(f), "0" * 64])
        assert result.exit_code != 0
        assert "FAIL" in result.output


class TestAcquireCommand:
    def test_acquire_creates_custody_file(self, tmp_path: Path) -> None:
        f = tmp_path / "image.dd"
        f.write_bytes(b"disk image")
        custody = tmp_path / "custody.json"
        runner = CliRunner()
        result = runner.invoke(cli, ["acquire", str(f), "-c", str(custody)])
        assert result.exit_code == 0
        assert custody.exists()
        data = json.loads(custody.read_text())
        assert data["chain"][0]["action"] == "ACQUIRED"


class TestLogCommand:
    def test_log_output(self, tmp_path: Path) -> None:
        f = tmp_path / "image.dd"
        f.write_bytes(b"evidence")
        custody = tmp_path / "custody.json"
        runner = CliRunner()
        runner.invoke(cli, ["acquire", str(f), "-c", str(custody), "-n", "Test case"])
        result = runner.invoke(cli, ["log", str(custody)])
        assert result.exit_code == 0
        assert "ACQUIRED" in result.output
        assert "Test case" in result.output
