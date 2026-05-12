"""Tests for project_100 core — GDPR/KVKK Compliance Auditor."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from project_100.core import (
    ComplianceFinding,
    DataAsset,
    audit_asset,
    audit_inventory_file,
    check_cross_border_transfer,
    check_dpo_notification,
    check_encryption,
    check_kvkk_explicit_consent,
    check_legal_basis,
    check_purpose_limitation,
    check_retention_period,
    check_sensitive_data_consent,
)


def _make_asset(**kwargs) -> DataAsset:  # type: ignore[return]
    """Build a compliant DataAsset, overriding specific fields."""
    defaults: dict = {
        "name": "test_asset",
        "data_categories": ["name", "email"],
        "purpose": "Marketing communications",
        "legal_basis": "consent",
        "retention_days": 365,
        "cross_border_transfer": False,
        "transfer_destination": "",
        "consent_obtained": True,
        "dpo_notified": True,
        "encryption_at_rest": True,
        "encryption_in_transit": True,
        "data_subjects": "customers",
        "controller": "ACME Corp",
    }
    defaults.update(kwargs)
    return DataAsset(**defaults)


# ── Legal basis ───────────────────────────────────────────────────────────────

class TestCheckLegalBasis:
    def test_valid_basis_returns_none(self) -> None:
        asset = _make_asset(legal_basis="consent")
        assert check_legal_basis(asset) is None

    def test_all_valid_bases(self) -> None:
        for basis in ("consent", "contract", "legal_obligation", "vital_interests",
                      "public_task", "legitimate_interests"):
            assert check_legal_basis(_make_asset(legal_basis=basis)) is None

    def test_invalid_basis_returns_finding(self) -> None:
        finding = check_legal_basis(_make_asset(legal_basis="none"))
        assert isinstance(finding, ComplianceFinding)
        assert finding.check_id == "GDPR-001"
        assert finding.severity == "CRITICAL"

    def test_empty_basis_returns_finding(self) -> None:
        finding = check_legal_basis(_make_asset(legal_basis=""))
        assert finding is not None
        assert finding.severity == "CRITICAL"


# ── Purpose limitation ────────────────────────────────────────────────────────

class TestCheckPurposeLimitation:
    def test_with_purpose_returns_none(self) -> None:
        assert check_purpose_limitation(_make_asset(purpose="Analytics")) is None

    def test_empty_purpose_returns_finding(self) -> None:
        finding = check_purpose_limitation(_make_asset(purpose=""))
        assert finding is not None
        assert finding.check_id == "GDPR-002"
        assert finding.severity == "HIGH"

    def test_whitespace_only_purpose_returns_finding(self) -> None:
        assert check_purpose_limitation(_make_asset(purpose="   ")) is not None


# ── Retention period ──────────────────────────────────────────────────────────

class TestCheckRetentionPeriod:
    def test_valid_retention_returns_none(self) -> None:
        assert check_retention_period(_make_asset(retention_days=180)) is None

    def test_zero_retention_returns_high(self) -> None:
        finding = check_retention_period(_make_asset(retention_days=0))
        assert finding is not None
        assert finding.check_id == "GDPR-003"
        assert finding.severity == "HIGH"

    def test_excessive_retention_returns_medium(self) -> None:
        finding = check_retention_period(_make_asset(retention_days=365 * 3))
        assert finding is not None
        assert finding.severity == "MEDIUM"

    def test_exactly_two_years_is_fine(self) -> None:
        assert check_retention_period(_make_asset(retention_days=365 * 2)) is None


# ── Cross-border transfer ─────────────────────────────────────────────────────

class TestCheckCrossBorderTransfer:
    def test_no_transfer_returns_none(self) -> None:
        assert check_cross_border_transfer(_make_asset(cross_border_transfer=False)) is None

    def test_adequate_country_returns_none(self) -> None:
        asset = _make_asset(cross_border_transfer=True, transfer_destination="Japan")
        assert check_cross_border_transfer(asset) is None

    def test_non_adequate_country_returns_critical(self) -> None:
        asset = _make_asset(cross_border_transfer=True, transfer_destination="Russia")
        finding = check_cross_border_transfer(asset)
        assert finding is not None
        assert finding.check_id == "GDPR-004"
        assert finding.severity == "CRITICAL"

    def test_uk_is_adequate(self) -> None:
        asset = _make_asset(cross_border_transfer=True, transfer_destination="uk")
        assert check_cross_border_transfer(asset) is None


# ── Sensitive data consent ────────────────────────────────────────────────────

class TestCheckSensitiveDataConsent:
    def test_no_sensitive_data_skipped(self) -> None:
        assert check_sensitive_data_consent(_make_asset()) is None

    def test_sensitive_without_consent_critical(self) -> None:
        asset = _make_asset(data_categories=["health"], consent_obtained=False)
        finding = check_sensitive_data_consent(asset)
        assert finding is not None
        assert finding.check_id == "GDPR-005"
        assert finding.severity == "CRITICAL"

    def test_sensitive_with_consent_ok(self) -> None:
        asset = _make_asset(data_categories=["biometric"], consent_obtained=True)
        assert check_sensitive_data_consent(asset) is None

    def test_special_category_flag(self) -> None:
        asset = _make_asset(special_category=True, consent_obtained=False)
        assert check_sensitive_data_consent(asset) is not None


# ── Encryption ────────────────────────────────────────────────────────────────

class TestCheckEncryption:
    def test_full_encryption_ok(self) -> None:
        assert check_encryption(_make_asset()) is None

    def test_missing_at_rest_high_for_sensitive(self) -> None:
        asset = _make_asset(data_categories=["health"], encryption_at_rest=False)
        finding = check_encryption(asset)
        assert finding is not None
        assert finding.severity == "HIGH"

    def test_missing_in_transit_medium_for_normal(self) -> None:
        asset = _make_asset(encryption_in_transit=False)
        finding = check_encryption(asset)
        assert finding is not None
        assert finding.severity == "MEDIUM"

    def test_both_missing_check_id(self) -> None:
        asset = _make_asset(encryption_at_rest=False, encryption_in_transit=False)
        finding = check_encryption(asset)
        assert finding is not None
        assert finding.check_id == "GDPR-006"


# ── DPO notification ──────────────────────────────────────────────────────────

class TestCheckDpoNotification:
    def test_no_sensitive_data_skipped(self) -> None:
        assert check_dpo_notification(_make_asset()) is None

    def test_sensitive_without_dpo_high(self) -> None:
        asset = _make_asset(data_categories=["health"], dpo_notified=False)
        finding = check_dpo_notification(asset)
        assert finding is not None
        assert finding.check_id == "GDPR-007"
        assert finding.severity == "HIGH"

    def test_sensitive_with_dpo_ok(self) -> None:
        asset = _make_asset(data_categories=["health"], dpo_notified=True)
        assert check_dpo_notification(asset) is None


# ── KVKK consent ─────────────────────────────────────────────────────────────

class TestCheckKvkkExplicitConsent:
    def test_consent_obtained_ok(self) -> None:
        assert check_kvkk_explicit_consent(_make_asset(consent_obtained=True)) is None

    def test_legal_obligation_ok(self) -> None:
        asset = _make_asset(consent_obtained=False, legal_basis="legal_obligation")
        assert check_kvkk_explicit_consent(asset) is None

    def test_no_consent_no_exception_high(self) -> None:
        asset = _make_asset(consent_obtained=False, legal_basis="legitimate_interests")
        finding = check_kvkk_explicit_consent(asset)
        assert finding is not None
        assert finding.check_id == "KVKK-001"
        assert finding.severity == "HIGH"


# ── audit_asset ───────────────────────────────────────────────────────────────

class TestAuditAsset:
    def test_clean_asset_no_findings(self) -> None:
        asset = _make_asset()
        assert audit_asset(asset) == []

    def test_problematic_asset_multiple_findings(self) -> None:
        asset = _make_asset(
            legal_basis="",
            purpose="",
            retention_days=0,
            encryption_at_rest=False,
        )
        findings = audit_asset(asset)
        ids = [f.check_id for f in findings]
        assert "GDPR-001" in ids
        assert "GDPR-002" in ids
        assert "GDPR-003" in ids


# ── audit_inventory_file ──────────────────────────────────────────────────────

class TestAuditInventoryFile:
    def test_single_clean_asset(self, tmp_path: Path) -> None:
        inv = tmp_path / "inv.json"
        inv.write_text(json.dumps({"assets": [{
            "name": "users_db", "data_categories": ["email"],
            "purpose": "auth", "legal_basis": "contract",
            "retention_days": 365, "cross_border_transfer": False,
            "transfer_destination": "", "consent_obtained": True,
            "dpo_notified": False, "encryption_at_rest": True,
            "encryption_in_transit": True, "data_subjects": "users",
            "controller": "ACME",
        }]}), encoding="utf-8")
        report = audit_inventory_file(inv)
        assert report.assets_audited == 1
        assert report.compliant

    def test_non_compliant_asset(self, tmp_path: Path) -> None:
        inv = tmp_path / "inv.json"
        inv.write_text(json.dumps({"assets": [{
            "name": "bad_asset", "data_categories": ["health"],
            "purpose": "unknown", "legal_basis": "none",
            "retention_days": 0, "cross_border_transfer": True,
            "transfer_destination": "Russia", "consent_obtained": False,
            "dpo_notified": False, "encryption_at_rest": False,
            "encryption_in_transit": False, "data_subjects": "patients",
            "controller": "BadCorp",
        }]}), encoding="utf-8")
        report = audit_inventory_file(inv)
        assert report.assets_audited == 1
        assert not report.compliant
        assert len(report.findings) > 0

    def test_to_dict_structure(self, tmp_path: Path) -> None:
        inv = tmp_path / "inv.json"
        inv.write_text(json.dumps({"assets": []}), encoding="utf-8")
        report = audit_inventory_file(inv)
        d = report.to_dict()
        assert "assets_audited" in d
        assert "findings" in d
        assert "by_severity" in d
