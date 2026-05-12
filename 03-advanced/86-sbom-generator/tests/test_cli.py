"""Tests for SBOM Generator CLI."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from project_86.cli import cli


class TestGenerateCommand:
    def test_cyclonedx(self, tmp_path: Path) -> None:
        f = tmp_path / "requirements.txt"
        f.write_text("requests==2.28.0\nflask>=2.3.0\n")
        out = tmp_path / "sbom.json"
        runner = CliRunner()
        result = runner.invoke(cli, ["generate", str(f), "-o", str(out)])
        assert result.exit_code == 0
        assert out.exists()
        data = json.loads(out.read_text())
        assert data["bomFormat"] == "CycloneDX"
        assert len(data["components"]) == 2

    def test_spdx(self, tmp_path: Path) -> None:
        f = tmp_path / "requirements.txt"
        f.write_text("click==8.1.0\n")
        out = tmp_path / "sbom.spdx.json"
        runner = CliRunner()
        result = runner.invoke(cli, ["generate", str(f), "--format", "spdx", "-o", str(out)])
        assert result.exit_code == 0
        data = json.loads(out.read_text())
        assert "spdxVersion" in data


class TestSummaryCommand:
    def test_summary(self, tmp_path: Path) -> None:
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": [
                {"name": "requests", "version": "2.28.0", "purl": "pkg:pypi/requests@2.28.0"},
            ],
        }
        f = tmp_path / "sbom.json"
        f.write_text(json.dumps(sbom))
        runner = CliRunner()
        result = runner.invoke(cli, ["summary", str(f)])
        assert result.exit_code == 0
        assert "requests" in result.output
