"""Tests for project_90 core — Terraform Security Scanner."""

from __future__ import annotations

from pathlib import Path

import pytest

from project_90.core import (
    HCLBlock,
    ScanReport,
    check_cloudtrail_logging,
    check_ec2_imdsv2,
    check_hardcoded_secrets,
    check_iam_admin_policy,
    check_rds_encryption,
    check_rds_public,
    check_s3_public_acl,
    check_s3_versioning,
    check_sg_unrestricted_ingress,
    check_sg_unrestricted_ssh,
    parse_hcl_blocks,
    scan_directory,
    scan_file,
)


# ── parse_hcl_blocks ──────────────────────────────────────────────────────────

class TestParseHCLBlocks:
    def test_parses_resource_block(self) -> None:
        content = '''
resource "aws_s3_bucket" "my_bucket" {
  bucket = "my-bucket"
}
'''
        blocks = parse_hcl_blocks(content)
        assert len(blocks) == 1
        assert blocks[0].resource_type == "aws_s3_bucket"
        assert blocks[0].resource_name == "my_bucket"

    def test_parses_multiple_blocks(self) -> None:
        content = '''
resource "aws_s3_bucket" "b1" {
  bucket = "b1"
}
resource "aws_instance" "web" {
  ami = "ami-12345"
}
'''
        blocks = parse_hcl_blocks(content)
        assert len(blocks) == 2

    def test_empty_content(self) -> None:
        assert parse_hcl_blocks("") == []


# ── S3 checks ─────────────────────────────────────────────────────────────────

class TestS3Checks:
    def _block(self, body: str) -> HCLBlock:
        return HCLBlock("resource", "aws_s3_bucket", "test", body, 1)

    def test_public_acl_triggers(self) -> None:
        b = self._block('acl = "public-read"')
        assert check_s3_public_acl(b) is not None

    def test_private_acl_no_trigger(self) -> None:
        b = self._block('acl = "private"')
        assert check_s3_public_acl(b) is None

    def test_no_versioning_triggers(self) -> None:
        b = self._block('bucket = "my-bucket"')
        assert check_s3_versioning(b) is not None

    def test_versioning_present_no_trigger(self) -> None:
        b = self._block('versioning {\n  enabled = true\n}')
        assert check_s3_versioning(b) is None

    def test_wrong_resource_type_ignored(self) -> None:
        b = HCLBlock("resource", "aws_instance", "test", 'acl = "public-read"', 1)
        assert check_s3_public_acl(b) is None


# ── Security group checks ─────────────────────────────────────────────────────

class TestSGChecks:
    def _block(self, body: str) -> HCLBlock:
        return HCLBlock("resource", "aws_security_group", "test", body, 1)

    def test_unrestricted_ingress(self) -> None:
        body = 'ingress {\n  cidr_blocks = ["0.0.0.0/0"]\n}'
        assert check_sg_unrestricted_ingress(self._block(body)) is not None

    def test_restricted_ingress_no_trigger(self) -> None:
        body = 'ingress {\n  cidr_blocks = ["10.0.0.0/8"]\n}'
        assert check_sg_unrestricted_ingress(self._block(body)) is None

    def test_ssh_open_to_world(self) -> None:
        body = 'ingress {\n  from_port = 22\n  cidr_blocks = ["0.0.0.0/0"]\n}'
        assert check_sg_unrestricted_ssh(self._block(body)) is not None

    def test_ssh_restricted_no_trigger(self) -> None:
        body = 'ingress {\n  from_port = 22\n  cidr_blocks = ["10.0.0.0/8"]\n}'
        assert check_sg_unrestricted_ssh(self._block(body)) is None


# ── IAM checks ────────────────────────────────────────────────────────────────

class TestIAMChecks:
    def test_admin_wildcard_policy(self) -> None:
        body = '''
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
'''
        b = HCLBlock("resource", "aws_iam_policy", "admin", body, 1)
        assert check_iam_admin_policy(b) is not None

    def test_limited_policy_no_trigger(self) -> None:
        body = '''
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = "s3:GetObject"
      Resource = "arn:aws:s3:::my-bucket/*"
    }]
  })
'''
        b = HCLBlock("resource", "aws_iam_policy", "limited", body, 1)
        assert check_iam_admin_policy(b) is None


# ── RDS checks ────────────────────────────────────────────────────────────────

class TestRDSChecks:
    def test_publicly_accessible_triggers(self) -> None:
        b = HCLBlock("resource", "aws_db_instance", "db", "publicly_accessible = true", 1)
        assert check_rds_public(b) is not None

    def test_not_publicly_accessible_no_trigger(self) -> None:
        b = HCLBlock("resource", "aws_db_instance", "db", "publicly_accessible = false", 1)
        assert check_rds_public(b) is None

    def test_no_encryption_triggers(self) -> None:
        b = HCLBlock("resource", "aws_db_instance", "db", 'engine = "mysql"', 1)
        assert check_rds_encryption(b) is not None

    def test_encryption_enabled_no_trigger(self) -> None:
        b = HCLBlock("resource", "aws_db_instance", "db", "storage_encrypted = true", 1)
        assert check_rds_encryption(b) is None


# ── EC2 checks ────────────────────────────────────────────────────────────────

class TestEC2Checks:
    def test_no_imdsv2_triggers(self) -> None:
        b = HCLBlock("resource", "aws_instance", "web", 'ami = "ami-123"', 1)
        assert check_ec2_imdsv2(b) is not None

    def test_imdsv2_required_no_trigger(self) -> None:
        body = 'metadata_options {\n  http_tokens = "required"\n}'
        b = HCLBlock("resource", "aws_instance", "web", body, 1)
        assert check_ec2_imdsv2(b) is None


# ── CloudTrail checks ─────────────────────────────────────────────────────────

class TestCloudTrailChecks:
    def test_logging_disabled_triggers(self) -> None:
        b = HCLBlock("resource", "aws_cloudtrail", "ct", "enable_logging = false", 1)
        assert check_cloudtrail_logging(b) is not None

    def test_logging_enabled_no_trigger(self) -> None:
        b = HCLBlock("resource", "aws_cloudtrail", "ct", "enable_logging = true", 1)
        assert check_cloudtrail_logging(b) is None


# ── Hardcoded secrets ─────────────────────────────────────────────────────────

class TestHardcodedSecrets:
    def test_hardcoded_password_triggers(self) -> None:
        b = HCLBlock("resource", "aws_db_instance", "db", 'password = "supersecret123"', 1)
        assert check_hardcoded_secrets(b) is not None

    def test_variable_reference_no_trigger(self) -> None:
        b = HCLBlock("resource", "aws_db_instance", "db", 'password = var.db_password', 1)
        assert check_hardcoded_secrets(b) is None


# ── scan_file / scan_directory ────────────────────────────────────────────────

class TestScanFile:
    def test_scan_file_returns_findings(self, tmp_path: Path) -> None:
        tf = tmp_path / "main.tf"
        tf.write_text('''
resource "aws_s3_bucket" "bad" {
  acl = "public-read"
}
''')
        findings = scan_file(tf)
        assert len(findings) > 0
        assert any(f.check_id == "TF-S3-001" for f in findings)

    def test_scan_clean_file(self, tmp_path: Path) -> None:
        tf = tmp_path / "main.tf"
        tf.write_text('''
resource "aws_s3_bucket" "ok" {
  bucket = "my-private-bucket"
  versioning {
    enabled = true
  }
}
''')
        findings = scan_file(tf)
        assert not any(f.check_id == "TF-S3-001" for f in findings)


class TestScanDirectory:
    def test_scan_directory(self, tmp_path: Path) -> None:
        tf1 = tmp_path / "main.tf"
        tf1.write_text('resource "aws_cloudtrail" "ct" {\n  enable_logging = false\n}\n')
        tf2 = tmp_path / "sg.tf"
        tf2.write_text('resource "aws_security_group" "sg" {\n  ingress {\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n')
        report = scan_directory(tmp_path)
        assert report.files_scanned == 2
        assert len(report.findings) >= 2

    def test_scan_empty_directory(self, tmp_path: Path) -> None:
        report = scan_directory(tmp_path)
        assert report.files_scanned == 0
        assert report.findings == []

    def test_to_dict_structure(self, tmp_path: Path) -> None:
        tf = tmp_path / "main.tf"
        tf.write_text('resource "aws_cloudtrail" "ct" {\n  enable_logging = false\n}\n')
        report = scan_directory(tmp_path)
        d = report.to_dict()
        assert "findings" in d
        assert "total_findings" in d
        assert "by_severity" in d
