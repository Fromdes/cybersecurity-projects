"""Tests for Container Image Scanner CLI."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from project_88.cli import cli
from project_88.core import create_mock_image_tarball


class TestScanCommand:
    def test_scan_root_image(self, tmp_path: Path) -> None:
        image_tar = tmp_path / "image.tar.gz"
        create_mock_image_tarball(image_tar, config={"config": {"User": "", "Env": [], "Cmd": []}})
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", str(image_tar)])
        assert result.exit_code == 0
        assert "IMG-001" in result.output

    def test_scan_output_file(self, tmp_path: Path) -> None:
        image_tar = tmp_path / "image.tar.gz"
        create_mock_image_tarball(image_tar)
        out = tmp_path / "report.json"
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", str(image_tar), "-o", str(out)])
        assert result.exit_code == 0
        assert out.exists()
        report = json.loads(out.read_text())
        assert "sha256" in report

    def test_exit_code_on_critical(self, tmp_path: Path) -> None:
        image_tar = tmp_path / "image.tar.gz"
        create_mock_image_tarball(image_tar, config={"config": {"User": "", "Env": [], "Cmd": []}})
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", str(image_tar), "--exit-code"])
        assert result.exit_code == 1
