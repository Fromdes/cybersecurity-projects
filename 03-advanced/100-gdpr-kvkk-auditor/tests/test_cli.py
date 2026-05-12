"""Tests for project_100 CLI — GDPR/KVKK Compliance Auditor."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from project_100.cli import cli


def _clean_inventory() -> dict:
    return {"assets": [{
        "name": "users_db",
        "data_categories": ["email", "name"],
        "purpose": "Authentication and user management",
        "legal_basis": "contract",
        "retention_days": 365,
        "cross_border_transfer": False,
        "transfer_destination": "",
        "consent_obtained": True,
        "dpo_notified": False,
        "encryption_at_rest": True,
        "encryption_in_transit": True,
        "data_subjects": "registered users",
        "controller": "ACME Corp",
    }]}


def _bad_inventory() -> dict:
    return {"assets": [{
        "name": "health_records",
        "data_categories": ["health", "biometric"],
        "purpose": "",
        "legal_basis": "none",
        "retention_days": 0,
        "cross_border_transfer": True,
        "transfer_destination": "Unknown Country",
        "consent_obtained": False,
        "dpo_notified": False,
        "encryption_at_rest": False,
        "encryption_in_transit": False,
        "data_subjects": "patients",
        "controller": "BadCorp",
        "special_category": True,
    }]}


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture()
def clean_inv(tmp_path: Path) -> Path:
    f = tmp_path / "clean.json"
    f.write_text(json.dumps(_clean_inventory()), encoding="utf-8")
    return f


@pytest.fixture()
def bad_inv(tmp_path: Path) -> Path:
    f = tmp_path / "bad.json"
    f.write_text(json.dumps(_bad_inventory()), encoding="utf-8")
    return f


class TestAuditCommand:
    def test_clean_inventory_compliant(self, runner: CliRunner, clean_inv: Path) -> None:
        result = runner.invoke(cli, ["audit", str(clean_inv)])
        assert result.exit_code == 0
        assert "COMPLIANT" in result.output

    def test_bad_inventory_non_compliant(self, runner: CliRunner, bad_inv: Path) -> None:
        result = runner.invoke(cli, ["audit", str(bad_inv)])
        assert result.exit_code == 0
        assert "NON-COMPLIANT" in result.output

    def test_bad_inventory_shows_findings(self, runner: CliRunner, bad_inv: Path) -> None:
        result = runner.invoke(cli, ["audit", str(bad_inv)])
        assert "GDPR-001" in result.output

    def test_exit_code_on_non_compliant(self, runner: CliRunner, bad_inv: Path) -> None:
        result = runner.invoke(cli, ["audit", str(bad_inv), "--exit-code"])
        assert result.exit_code == 1

    def test_no_exit_code_on_compliant(self, runner: CliRunner, clean_inv: Path) -> None:
        result = runner.invoke(cli, ["audit", str(clean_inv), "--exit-code"])
        assert result.exit_code == 0

    def test_output_json(self, runner: CliRunner, bad_inv: Path, tmp_path: Path) -> None:
        out = tmp_path / "report.json"
        result = runner.invoke(cli, ["audit", str(bad_inv), "-o", str(out)])
        assert result.exit_code == 0
        assert out.exists()
        data = json.loads(out.read_text())
        assert "findings" in data
        assert "assets_audited" in data

    def test_min_severity_filter(self, runner: CliRunner, bad_inv: Path) -> None:
        result = runner.invoke(cli, ["audit", str(bad_inv), "--min-severity", "CRITICAL"])
        assert result.exit_code == 0
        assert "CRITICAL" in result.output

    def test_regulation_filter(self, runner: CliRunner, bad_inv: Path) -> None:
        result = runner.invoke(cli, ["audit", str(bad_inv), "--regulation", "KVKK"])
        assert result.exit_code == 0
        assert "KVKK" in result.output

    def test_missing_file(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["audit", "/nonexistent/inventory.json"])
        assert result.exit_code != 0


class TestVersionOption:
    def test_version_flag(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output
