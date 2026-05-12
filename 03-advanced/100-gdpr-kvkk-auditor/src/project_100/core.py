"""GDPR/KVKK Compliance Auditor — check data assets against regulation requirements."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# ── Data models ───────────────────────────────────────────────────────────────

SENSITIVE_CATEGORIES: frozenset[str] = frozenset({
    "health", "biometric", "genetic", "racial", "ethnic", "political",
    "religious", "philosophical", "sexual_orientation", "criminal",
    "trade_union",
})

RETENTION_WARNING_DAYS = 365 * 2  # 2 years
GDPR_ADEQUACY_COUNTRIES: frozenset[str] = frozenset({
    "andorra", "argentina", "canada", "faroe_islands", "guernsey",
    "israel", "isle_of_man", "japan", "jersey", "new_zealand",
    "republic_of_korea", "switzerland", "united_kingdom", "uruguay",
    "eu", "eea", "uk",
})


@dataclass(frozen=True)
class DataAsset:
    """A data asset representing a data store or processing activity."""

    name: str
    data_categories: list[str]
    purpose: str
    legal_basis: str
    retention_days: int
    cross_border_transfer: bool
    transfer_destination: str
    consent_obtained: bool
    dpo_notified: bool
    encryption_at_rest: bool
    encryption_in_transit: bool
    data_subjects: str
    controller: str
    processor: str = ""
    special_category: bool = False

    @property
    def has_sensitive_data(self) -> bool:
        """Return True if any data category is sensitive/special category."""
        cats = {c.lower() for c in self.data_categories}
        return bool(cats & SENSITIVE_CATEGORIES) or self.special_category


# ── Compliance finding ────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ComplianceFinding:
    """A compliance violation or warning."""

    check_id: str
    regulation: str
    severity: str
    title: str
    description: str
    asset_name: str
    article: str
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "check_id": self.check_id,
            "regulation": self.regulation,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "asset_name": self.asset_name,
            "article": self.article,
            "recommendation": self.recommendation,
        }


# ── Compliance checks ─────────────────────────────────────────────────────────

def check_legal_basis(asset: DataAsset) -> ComplianceFinding | None:
    """GDPR-001: Processing must have a valid legal basis."""
    valid_bases = {"consent", "contract", "legal_obligation", "vital_interests",
                   "public_task", "legitimate_interests"}
    if not asset.legal_basis or asset.legal_basis.lower() not in valid_bases:
        return ComplianceFinding(
            check_id="GDPR-001",
            regulation="GDPR",
            severity="CRITICAL",
            title="Missing or invalid legal basis for processing",
            description=f"{asset.name}: legal_basis={asset.legal_basis!r}",
            asset_name=asset.name,
            article="Article 6 GDPR",
            recommendation="Define a valid legal basis: consent, contract, legal_obligation, "
                           "vital_interests, public_task, or legitimate_interests",
        )
    return None


def check_purpose_limitation(asset: DataAsset) -> ComplianceFinding | None:
    """GDPR-002: Purpose must be specified."""
    if not asset.purpose or asset.purpose.strip() == "":
        return ComplianceFinding(
            check_id="GDPR-002",
            regulation="GDPR",
            severity="HIGH",
            title="Purpose not specified",
            description=f"{asset.name}: no processing purpose defined",
            asset_name=asset.name,
            article="Article 5(1)(b) GDPR",
            recommendation="Specify a clear, explicit purpose for data processing",
        )
    return None


def check_retention_period(asset: DataAsset) -> ComplianceFinding | None:
    """GDPR-003: Excessive retention periods."""
    if asset.retention_days <= 0:
        return ComplianceFinding(
            check_id="GDPR-003",
            regulation="GDPR / KVKK",
            severity="HIGH",
            title="Retention period not defined",
            description=f"{asset.name}: retention_days={asset.retention_days}",
            asset_name=asset.name,
            article="Article 5(1)(e) GDPR / KVKK Article 7",
            recommendation="Define a specific data retention period and delete when no longer needed",
        )
    if asset.retention_days > RETENTION_WARNING_DAYS:
        return ComplianceFinding(
            check_id="GDPR-003",
            regulation="GDPR / KVKK",
            severity="MEDIUM",
            title=f"Retention period exceeds {RETENTION_WARNING_DAYS // 365} years",
            description=f"{asset.name}: {asset.retention_days} days retention",
            asset_name=asset.name,
            article="Article 5(1)(e) GDPR / KVKK Article 7",
            recommendation="Review if long retention is necessary; document justification",
        )
    return None


def check_cross_border_transfer(asset: DataAsset) -> ComplianceFinding | None:
    """GDPR-004 / KVKK-004: Cross-border transfers require adequacy or safeguards."""
    if not asset.cross_border_transfer:
        return None
    dest = asset.transfer_destination.lower().replace(" ", "_")
    if dest not in GDPR_ADEQUACY_COUNTRIES:
        return ComplianceFinding(
            check_id="GDPR-004",
            regulation="GDPR / KVKK",
            severity="CRITICAL",
            title="Cross-border transfer to non-adequate country",
            description=f"{asset.name}: transfer to {asset.transfer_destination!r}",
            asset_name=asset.name,
            article="Chapter V GDPR / KVKK Article 9",
            recommendation="Use SCCs, BCRs, or obtain explicit consent; or restrict transfer to adequate countries",
        )
    return None


def check_sensitive_data_consent(asset: DataAsset) -> ComplianceFinding | None:
    """GDPR-005: Special category data requires explicit consent."""
    if not asset.has_sensitive_data:
        return None
    if not asset.consent_obtained:
        return ComplianceFinding(
            check_id="GDPR-005",
            regulation="GDPR / KVKK",
            severity="CRITICAL",
            title="Special category data processed without explicit consent",
            description=f"{asset.name}: sensitive categories {asset.data_categories}",
            asset_name=asset.name,
            article="Article 9 GDPR / KVKK Article 6",
            recommendation="Obtain explicit consent or identify an Article 9(2) exemption",
        )
    return None


def check_encryption(asset: DataAsset) -> ComplianceFinding | None:
    """GDPR-006: Encryption as technical safeguard."""
    if not asset.encryption_at_rest or not asset.encryption_in_transit:
        missing = []
        if not asset.encryption_at_rest:
            missing.append("at-rest")
        if not asset.encryption_in_transit:
            missing.append("in-transit")
        sev = "HIGH" if asset.has_sensitive_data else "MEDIUM"
        return ComplianceFinding(
            check_id="GDPR-006",
            regulation="GDPR",
            severity=sev,
            title=f"Missing encryption: {', '.join(missing)}",
            description=f"{asset.name}: encryption gaps detected",
            asset_name=asset.name,
            article="Article 32 GDPR",
            recommendation="Implement AES-256 at rest and TLS 1.2+ in transit",
        )
    return None


def check_dpo_notification(asset: DataAsset) -> ComplianceFinding | None:
    """GDPR-007: Large-scale or sensitive processing requires DPO involvement."""
    if asset.has_sensitive_data and not asset.dpo_notified:
        return ComplianceFinding(
            check_id="GDPR-007",
            regulation="GDPR / KVKK",
            severity="HIGH",
            title="DPO not notified for sensitive data processing",
            description=f"{asset.name}: special category data without DPO review",
            asset_name=asset.name,
            article="Article 37-39 GDPR / KVKK Article 12",
            recommendation="Notify Data Protection Officer; conduct DPIA if required",
        )
    return None


def check_kvkk_explicit_consent(asset: DataAsset) -> ComplianceFinding | None:
    """KVKK-001: Turkish law requires explicit consent for all personal data processing."""
    if not asset.consent_obtained and asset.legal_basis.lower() not in (
        "legal_obligation", "vital_interests", "contract"
    ):
        return ComplianceFinding(
            check_id="KVKK-001",
            regulation="KVKK",
            severity="HIGH",
            title="KVKK explicit consent not obtained",
            description=f"{asset.name}: processing without explicit consent or legal exception",
            asset_name=asset.name,
            article="KVKK Article 5-6",
            recommendation="Obtain explicit informed consent or document legal exception",
        )
    return None


_CHECK_FUNCTIONS = (
    check_legal_basis,
    check_purpose_limitation,
    check_retention_period,
    check_cross_border_transfer,
    check_sensitive_data_consent,
    check_encryption,
    check_dpo_notification,
    check_kvkk_explicit_consent,
)


# ── Compliance report ─────────────────────────────────────────────────────────

@dataclass
class ComplianceReport:
    """Full compliance audit report."""

    findings: list[ComplianceFinding]
    assets_audited: int
    source: str

    @property
    def compliant(self) -> bool:
        """Return True only if there are no CRITICAL or HIGH findings."""
        return not any(f.severity in ("CRITICAL", "HIGH") for f in self.findings)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        by_reg: dict[str, int] = {}
        by_sev: dict[str, int] = {}
        for f in self.findings:
            by_reg[f.regulation] = by_reg.get(f.regulation, 0) + 1
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        return {
            "source": self.source,
            "assets_audited": self.assets_audited,
            "compliant": self.compliant,
            "total_findings": len(self.findings),
            "by_regulation": by_reg,
            "by_severity": by_sev,
            "findings": [f.to_dict() for f in self.findings],
        }


def audit_asset(asset: DataAsset) -> list[ComplianceFinding]:
    """Run all compliance checks against a single data asset."""
    findings: list[ComplianceFinding] = []
    for check_fn in _CHECK_FUNCTIONS:
        result = check_fn(asset)
        if result is not None:
            findings.append(result)
    return findings


def _parse_asset(data: dict[str, Any]) -> DataAsset:
    """Parse a DataAsset from a dict."""
    return DataAsset(
        name=data["name"],
        data_categories=data.get("data_categories", []),
        purpose=data.get("purpose", ""),
        legal_basis=data.get("legal_basis", ""),
        retention_days=int(data.get("retention_days", 0)),
        cross_border_transfer=bool(data.get("cross_border_transfer", False)),
        transfer_destination=data.get("transfer_destination", ""),
        consent_obtained=bool(data.get("consent_obtained", False)),
        dpo_notified=bool(data.get("dpo_notified", False)),
        encryption_at_rest=bool(data.get("encryption_at_rest", False)),
        encryption_in_transit=bool(data.get("encryption_in_transit", False)),
        data_subjects=data.get("data_subjects", ""),
        controller=data.get("controller", ""),
        processor=data.get("processor", ""),
        special_category=bool(data.get("special_category", False)),
    )


def audit_inventory_file(path: Path) -> ComplianceReport:
    """Audit all data assets in a JSON inventory file."""
    data = json.loads(path.read_text(encoding="utf-8"))
    assets_data = data.get("assets", [])
    all_findings: list[ComplianceFinding] = []
    for asset_data in assets_data:
        try:
            asset = _parse_asset(asset_data)
            all_findings.extend(audit_asset(asset))
        except (KeyError, ValueError):
            continue
    return ComplianceReport(
        findings=all_findings,
        assets_audited=len(assets_data),
        source=str(path),
    )
