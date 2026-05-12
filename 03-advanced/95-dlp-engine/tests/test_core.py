"""Tests for project_95 core — DLP Engine."""

from __future__ import annotations

from pathlib import Path

from project_95.core import (
    DEFAULT_RULES,
    DLPRule,
    redact_text,
    scan_directory,
    scan_file,
    scan_text,
)


def _rule_by_id(rule_id: str) -> DLPRule:
    for r in DEFAULT_RULES:
        if r.rule_id == rule_id:
            return r
    raise KeyError(rule_id)


# ── Individual rule tests ─────────────────────────────────────────────────────

class TestSSNRule:
    def test_detects_ssn(self) -> None:
        rule = _rule_by_id("DLP-001")
        assert rule.matches("My SSN is 123-45-6789") != []

    def test_no_false_positive_all_zeros(self) -> None:
        rule = _rule_by_id("DLP-001")
        assert rule.matches("000-00-0000") == []


class TestCreditCardRule:
    def test_detects_visa(self) -> None:
        rule = _rule_by_id("DLP-002")
        assert rule.matches("Card: 4532015112830366") != []

    def test_no_match_random_number(self) -> None:
        rule = _rule_by_id("DLP-002")
        assert rule.matches("12345 not a card") == []


class TestEmailRule:
    def test_detects_email(self) -> None:
        rule = _rule_by_id("DLP-003")
        assert rule.matches("Contact: user@example.com for info") != []

    def test_no_match_invalid_email(self) -> None:
        rule = _rule_by_id("DLP-003")
        assert rule.matches("not-an-email") == []


class TestAWSKeyRule:
    def test_detects_aws_access_key(self) -> None:
        rule = _rule_by_id("DLP-006")
        assert rule.matches("key = AKIAIOSFODNN7EXAMPLE") != []

    def test_no_match_random_uppercase(self) -> None:
        rule = _rule_by_id("DLP-006")
        assert rule.matches("HELLO WORLD 1234567890ABCDEF") == []


class TestPrivateKeyRule:
    def test_detects_rsa_private_key(self) -> None:
        rule = _rule_by_id("DLP-007")
        assert rule.matches("-----BEGIN RSA PRIVATE KEY-----") != []

    def test_detects_openssh_private_key(self) -> None:
        rule = _rule_by_id("DLP-007")
        assert rule.matches("-----BEGIN OPENSSH PRIVATE KEY-----") != []


class TestPasswordRule:
    def test_detects_password_assignment(self) -> None:
        rule = _rule_by_id("DLP-008")
        assert rule.matches('password = "supersecret123"') != []

    def test_no_match_empty_password(self) -> None:
        rule = _rule_by_id("DLP-008")
        assert rule.matches("password = ") == []


class TestDatabaseURLRule:
    def test_detects_postgres_url(self) -> None:
        rule = _rule_by_id("DLP-009")
        assert rule.matches("postgresql://admin:secret@db.internal/mydb") != []

    def test_detects_mysql_url(self) -> None:
        rule = _rule_by_id("DLP-009")
        assert rule.matches("mysql://user:pass123@host:3306/dbname") != []


class TestGitHubTokenRule:
    def test_detects_ghp_token(self) -> None:
        rule = _rule_by_id("DLP-010")
        assert rule.matches("token = ghp_ABCDEF1234567890ABCDEF1234567890ABCD") != []


class TestJWTRule:
    def test_detects_jwt(self) -> None:
        rule = _rule_by_id("DLP-013")
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        assert rule.matches(jwt) != []


# ── scan_text ─────────────────────────────────────────────────────────────────

class TestScanText:
    def test_returns_findings(self) -> None:
        text = "Contact alice@example.com for SSN 123-45-6789"
        findings = scan_text(text)
        ids = {f.rule_id for f in findings}
        assert "DLP-001" in ids
        assert "DLP-003" in ids

    def test_empty_text_no_findings(self) -> None:
        assert scan_text("") == []

    def test_finding_has_correct_line_number(self) -> None:
        text = "line1\nSSN: 123-45-6789\nline3"
        findings = scan_text(text)
        ssn = [f for f in findings if f.rule_id == "DLP-001"]
        assert ssn[0].line_number == 2

    def test_custom_rules_only(self) -> None:
        email_rule = _rule_by_id("DLP-003")
        text = "email@example.com and 123-45-6789"
        findings = scan_text(text, rules=(email_rule,))
        assert all(f.rule_id == "DLP-003" for f in findings)

    def test_finding_matched_text(self) -> None:
        findings = scan_text("admin@corp.com is the contact")
        email = [f for f in findings if f.rule_id == "DLP-003"]
        assert "admin@corp.com" in email[0].matched_text

    def test_to_dict_structure(self) -> None:
        findings = scan_text("user@example.com")
        d = findings[0].to_dict()
        assert set(d.keys()) >= {"rule_id", "rule_name", "category", "severity",
                                  "file_path", "line_number", "matched_text"}


# ── redact_text ───────────────────────────────────────────────────────────────

class TestRedactText:
    def test_redacts_email(self) -> None:
        result = redact_text("Contact: admin@example.com")
        assert "admin@example.com" not in result
        assert "[REDACTED]" in result

    def test_redacts_ssn(self) -> None:
        result = redact_text("SSN: 123-45-6789")
        assert "123-45-6789" not in result

    def test_clean_text_unchanged(self) -> None:
        text = "This is clean text with no sensitive data."
        assert redact_text(text) == text


# ── scan_file ─────────────────────────────────────────────────────────────────

class TestScanFile:
    def test_scan_file_with_email(self, tmp_path: Path) -> None:
        f = tmp_path / "data.txt"
        f.write_text("contact: user@example.com\n")
        findings = scan_file(f)
        assert any(f.rule_id == "DLP-003" for f in findings)

    def test_skip_binary_extension(self, tmp_path: Path) -> None:
        f = tmp_path / "image.jpg"
        f.write_bytes(b"\xff\xd8\xff")
        assert scan_file(f) == []


# ── scan_directory ────────────────────────────────────────────────────────────

class TestScanDirectory:
    def test_scan_directory(self, tmp_path: Path) -> None:
        (tmp_path / "a.txt").write_text("AWS_KEY = AKIAIOSFODNN7EXAMPLE\n")
        (tmp_path / "b.txt").write_text("normal content\n")
        report = scan_directory(tmp_path)
        assert report.files_scanned == 2
        assert len(report.findings) >= 1

    def test_to_dict_structure(self, tmp_path: Path) -> None:
        (tmp_path / "test.txt").write_text("user@example.com\n")
        report = scan_directory(tmp_path)
        d = report.to_dict()
        assert "findings" in d
        assert "by_category" in d
        assert "by_severity" in d
        assert "total_findings" in d
