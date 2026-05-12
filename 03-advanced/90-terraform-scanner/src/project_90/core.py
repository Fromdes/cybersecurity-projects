"""Terraform Security Scanner — static analysis for Terraform HCL configurations."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# ── Check definitions ─────────────────────────────────────────────────────────

@dataclass(frozen=True)
class TFCheck:
    """A single Terraform security check."""

    check_id: str
    severity: str
    title: str
    resource_types: frozenset[str]
    description: str
    mitre_technique: str = "T1078"


@dataclass(frozen=True)
class TFFinding:
    """A finding from a Terraform security check."""

    check_id: str
    severity: str
    title: str
    resource_type: str
    resource_name: str
    file_path: str
    line_number: int
    detail: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "check_id": self.check_id,
            "severity": self.severity,
            "title": self.title,
            "resource_type": self.resource_type,
            "resource_name": self.resource_name,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "detail": self.detail,
        }


# ── HCL block parser (regex-based, no external deps) ─────────────────────────

@dataclass
class HCLBlock:
    """A parsed HCL resource/data/provider block."""

    block_type: str
    resource_type: str
    resource_name: str
    body: str
    start_line: int


_BLOCK_HEADER = re.compile(
    r'^(resource|data|provider|module)\s+"([^"]+)"\s+"([^"]+)"\s*\{',
    re.MULTILINE,
)
_PROVIDER_HEADER = re.compile(r'^(provider)\s+"([^"]+)"\s*\{', re.MULTILINE)


def parse_hcl_blocks(content: str) -> list[HCLBlock]:
    """Extract top-level blocks from HCL content using brace counting."""
    blocks: list[HCLBlock] = []
    lines = content.splitlines(keepends=True)
    i = 0
    while i < len(lines):
        line = lines[i]
        m = _BLOCK_HEADER.match(line.strip())
        if not m:
            m2 = _PROVIDER_HEADER.match(line.strip())
            if m2:
                block_type = m2.group(1)
                resource_type = m2.group(2)
                resource_name = "__provider__"
                start_line = i + 1
                body, i = _extract_body(lines, i)
                blocks.append(HCLBlock(block_type, resource_type, resource_name, body, start_line))
                continue
            i += 1
            continue
        block_type = m.group(1)
        resource_type = m.group(2)
        resource_name = m.group(3)
        start_line = i + 1
        body, i = _extract_body(lines, i)
        blocks.append(HCLBlock(block_type, resource_type, resource_name, body, start_line))
    return blocks


def _extract_body(lines: list[str], start: int) -> tuple[str, int]:
    """Extract the body of a brace-delimited block starting at *start*."""
    depth = 0
    body_lines: list[str] = []
    i = start
    while i < len(lines):
        line = lines[i]
        depth += line.count("{") - line.count("}")
        body_lines.append(line)
        i += 1
        if depth <= 0:
            break
    return "".join(body_lines), i


# ── Security checks ───────────────────────────────────────────────────────────

def _attr(body: str, key: str) -> str | None:
    """Extract the value of an attribute from an HCL body."""
    m = re.search(rf'\b{re.escape(key)}\s*=\s*(.+)', body)
    return m.group(1).strip() if m else None


def _is_false(val: str | None) -> bool:
    return val is not None and val.strip().lower() in ("false", '"false"', "0")


def _is_true(val: str | None) -> bool:
    return val is not None and val.strip().lower() in ("true", '"true"', "1")


def _contains(body: str, pattern: str) -> bool:
    return bool(re.search(pattern, body, re.IGNORECASE))


def check_s3_public_acl(block: HCLBlock) -> TFFinding | None:
    """TF-S3-001: S3 bucket with public-read or public-read-write ACL."""
    if block.resource_type != "aws_s3_bucket":
        return None
    acl = _attr(block.body, "acl")
    if acl and re.search(r'public', acl, re.IGNORECASE):
        return TFFinding(
            check_id="TF-S3-001",
            severity="CRITICAL",
            title="S3 bucket with public ACL",
            resource_type=block.resource_type,
            resource_name=block.resource_name,
            file_path="",
            line_number=block.start_line,
            detail=f"acl = {acl}",
        )
    return None


def check_s3_versioning(block: HCLBlock) -> TFFinding | None:
    """TF-S3-002: S3 bucket without versioning enabled."""
    if block.resource_type != "aws_s3_bucket":
        return None
    if not _contains(block.body, r'versioning'):
        return TFFinding(
            check_id="TF-S3-002",
            severity="MEDIUM",
            title="S3 bucket versioning not configured",
            resource_type=block.resource_type,
            resource_name=block.resource_name,
            file_path="",
            line_number=block.start_line,
            detail="No versioning block found",
        )
    return None


def check_sg_unrestricted_ingress(block: HCLBlock) -> TFFinding | None:
    """TF-SG-001: Security group with 0.0.0.0/0 ingress."""
    if block.resource_type not in ("aws_security_group", "aws_security_group_rule"):
        return None
    if _contains(block.body, r'0\.0\.0\.0/0') and _contains(block.body, r'ingress'):
        return TFFinding(
            check_id="TF-SG-001",
            severity="HIGH",
            title="Security group allows unrestricted ingress",
            resource_type=block.resource_type,
            resource_name=block.resource_name,
            file_path="",
            line_number=block.start_line,
            detail="cidr_blocks = 0.0.0.0/0 in ingress rule",
        )
    return None


def check_sg_unrestricted_ssh(block: HCLBlock) -> TFFinding | None:
    """TF-SG-002: Security group allows SSH from anywhere."""
    if block.resource_type not in ("aws_security_group", "aws_security_group_rule"):
        return None
    if (
        _contains(block.body, r'0\.0\.0\.0/0')
        and _contains(block.body, r'\bfrom_port\s*=\s*22\b')
    ):
        return TFFinding(
            check_id="TF-SG-002",
            severity="CRITICAL",
            title="Security group allows SSH from 0.0.0.0/0",
            resource_type=block.resource_type,
            resource_name=block.resource_name,
            file_path="",
            line_number=block.start_line,
            detail="Port 22 open to 0.0.0.0/0",
        )
    return None


def check_iam_admin_policy(block: HCLBlock) -> TFFinding | None:
    """TF-IAM-001: IAM policy with wildcard Action and Resource."""
    if block.resource_type not in ("aws_iam_policy", "aws_iam_role_policy"):
        return None
    action_re = r'["\']?Action["\']?\s*[=:]\s*["\']?\*["\']?'
    resource_re = r'["\']?Resource["\']?\s*[=:]\s*["\']?\*["\']?'
    if _contains(block.body, action_re) and _contains(block.body, resource_re):
        return TFFinding(
            check_id="TF-IAM-001",
            severity="CRITICAL",
            title="IAM policy grants full admin access",
            resource_type=block.resource_type,
            resource_name=block.resource_name,
            file_path="",
            line_number=block.start_line,
            detail='Action: "*", Resource: "*"',
        )
    return None


def check_rds_public(block: HCLBlock) -> TFFinding | None:
    """TF-RDS-001: RDS instance publicly accessible."""
    if block.resource_type not in ("aws_db_instance", "aws_rds_cluster"):
        return None
    if _is_true(_attr(block.body, "publicly_accessible")):
        return TFFinding(
            check_id="TF-RDS-001",
            severity="HIGH",
            title="RDS instance publicly accessible",
            resource_type=block.resource_type,
            resource_name=block.resource_name,
            file_path="",
            line_number=block.start_line,
            detail="publicly_accessible = true",
        )
    return None


def check_rds_encryption(block: HCLBlock) -> TFFinding | None:
    """TF-RDS-002: RDS instance without storage encryption."""
    if block.resource_type not in ("aws_db_instance",):
        return None
    val = _attr(block.body, "storage_encrypted")
    if val is None or _is_false(val):
        return TFFinding(
            check_id="TF-RDS-002",
            severity="HIGH",
            title="RDS instance storage not encrypted",
            resource_type=block.resource_type,
            resource_name=block.resource_name,
            file_path="",
            line_number=block.start_line,
            detail=f"storage_encrypted = {val or 'not set'}",
        )
    return None


def check_ec2_imdsv2(block: HCLBlock) -> TFFinding | None:
    """TF-EC2-001: EC2 instance without IMDSv2 enforcement."""
    if block.resource_type != "aws_instance":
        return None
    if not _contains(block.body, r'metadata_options') or not _contains(
        block.body, r'http_tokens\s*=\s*"required"'
    ):
        return TFFinding(
            check_id="TF-EC2-001",
            severity="MEDIUM",
            title="EC2 instance does not enforce IMDSv2",
            resource_type=block.resource_type,
            resource_name=block.resource_name,
            file_path="",
            line_number=block.start_line,
            detail="metadata_options.http_tokens not set to required",
        )
    return None


def check_cloudtrail_logging(block: HCLBlock) -> TFFinding | None:
    """TF-CT-001: CloudTrail with logging disabled."""
    if block.resource_type != "aws_cloudtrail":
        return None
    if _is_false(_attr(block.body, "enable_logging")):
        return TFFinding(
            check_id="TF-CT-001",
            severity="HIGH",
            title="CloudTrail logging disabled",
            resource_type=block.resource_type,
            resource_name=block.resource_name,
            file_path="",
            line_number=block.start_line,
            detail="enable_logging = false",
        )
    return None


def check_hardcoded_secrets(block: HCLBlock) -> TFFinding | None:
    """TF-SEC-001: Hardcoded credentials in resource attributes."""
    SECRET_ATTRS = re.compile(
        r'\b(password|secret|private_key|access_key|api_key|token)\s*=\s*"[^"${}]{8,}"',
        re.IGNORECASE,
    )
    m = SECRET_ATTRS.search(block.body)
    if m:
        return TFFinding(
            check_id="TF-SEC-001",
            severity="CRITICAL",
            title="Hardcoded secret in Terraform configuration",
            resource_type=block.resource_type,
            resource_name=block.resource_name,
            file_path="",
            line_number=block.start_line,
            detail=f"Attribute: {m.group(1)}",
        )
    return None


_CHECK_FUNCTIONS = (
    check_s3_public_acl,
    check_s3_versioning,
    check_sg_unrestricted_ingress,
    check_sg_unrestricted_ssh,
    check_iam_admin_policy,
    check_rds_public,
    check_rds_encryption,
    check_ec2_imdsv2,
    check_cloudtrail_logging,
    check_hardcoded_secrets,
)


# ── Scan engine ───────────────────────────────────────────────────────────────

@dataclass
class ScanReport:
    """Full Terraform scan report."""

    findings: list[TFFinding]
    files_scanned: int
    source: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        by_sev: dict[str, int] = {}
        for f in self.findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        return {
            "source": self.source,
            "files_scanned": self.files_scanned,
            "total_findings": len(self.findings),
            "by_severity": by_sev,
            "findings": [f.to_dict() for f in self.findings],
        }


def scan_file(path: Path) -> list[TFFinding]:
    """Scan a single Terraform .tf file and return findings."""
    content = path.read_text(encoding="utf-8", errors="replace")
    blocks = parse_hcl_blocks(content)
    findings: list[TFFinding] = []
    for block in blocks:
        for check_fn in _CHECK_FUNCTIONS:
            result = check_fn(block)
            if result is not None:
                findings.append(TFFinding(
                    check_id=result.check_id,
                    severity=result.severity,
                    title=result.title,
                    resource_type=result.resource_type,
                    resource_name=result.resource_name,
                    file_path=str(path),
                    line_number=result.line_number,
                    detail=result.detail,
                ))
    return findings


def scan_directory(path: Path) -> ScanReport:
    """Scan all .tf files in a directory recursively."""
    tf_files = list(path.rglob("*.tf"))
    all_findings: list[TFFinding] = []
    for tf_file in tf_files:
        all_findings.extend(scan_file(tf_file))
    return ScanReport(
        findings=all_findings,
        files_scanned=len(tf_files),
        source=str(path),
    )
