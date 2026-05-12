"""Tests for Input Sanitization Library core logic."""

from __future__ import annotations

import pytest

from project_44.core import (
    ThreatType,
    detect_threats,
    sanitize_filename,
    sanitize_text,
    strip_html_tags,
    strip_null_bytes,
    validate_email,
    validate_integer,
)


class TestDetectThreats:
    # XSS
    def test_script_tag(self) -> None:
        threats = detect_threats("<script>alert(1)</script>")
        types = [t.threat_type for t in threats]
        assert ThreatType.XSS in types

    def test_onerror_handler(self) -> None:
        threats = detect_threats('<img onerror="evil()">')
        assert any(t.threat_type == ThreatType.XSS for t in threats)

    def test_javascript_proto(self) -> None:
        threats = detect_threats("javascript:void(0)")
        assert any(t.threat_type == ThreatType.XSS for t in threats)

    def test_iframe(self) -> None:
        threats = detect_threats('<iframe src="evil.com">')
        assert any(t.threat_type == ThreatType.XSS for t in threats)

    # SQLi
    def test_union_select(self) -> None:
        threats = detect_threats("' UNION SELECT * FROM users")
        assert any(t.threat_type == ThreatType.SQLI for t in threats)

    def test_or_tautology(self) -> None:
        threats = detect_threats("' OR '1'='1")
        assert any(t.threat_type == ThreatType.SQLI for t in threats)

    def test_drop_table(self) -> None:
        threats = detect_threats("; DROP TABLE users;")
        assert any(t.threat_type == ThreatType.SQLI for t in threats)

    def test_sqli_comment(self) -> None:
        threats = detect_threats("admin'--")
        assert any(t.threat_type == ThreatType.SQLI for t in threats)

    # Path traversal
    def test_dotdot_slash(self) -> None:
        threats = detect_threats("../../etc/passwd")
        assert any(t.threat_type == ThreatType.PATH_TRAVERSAL for t in threats)

    def test_url_encoded_traversal(self) -> None:
        threats = detect_threats("%2e%2e%2fetc%2fpasswd")
        assert any(t.threat_type == ThreatType.PATH_TRAVERSAL for t in threats)

    # Command injection
    def test_semicolon_cmd(self) -> None:
        threats = detect_threats("file.txt; rm -rf /")
        assert any(t.threat_type == ThreatType.CMD_INJECTION for t in threats)

    def test_pipe_cmd(self) -> None:
        threats = detect_threats("foo | cat /etc/passwd")
        assert any(t.threat_type == ThreatType.CMD_INJECTION for t in threats)

    # Null byte
    def test_null_byte(self) -> None:
        threats = detect_threats("file\x00.txt")
        assert any(t.threat_type == ThreatType.NULL_BYTE for t in threats)

    # Clean
    def test_clean_input(self) -> None:
        threats = detect_threats("Hello, world! This is safe.")
        assert threats == []

    def test_clean_email(self) -> None:
        threats = detect_threats("user@example.com")
        assert threats == []


class TestSanitizeText:
    def test_strips_script_tag(self) -> None:
        result = sanitize_text("<script>alert(1)</script>Hello")
        assert "<script>" not in result.sanitized
        assert "Hello" in result.sanitized

    def test_removes_null_bytes(self) -> None:
        result = sanitize_text("file\x00name")
        assert "\x00" not in result.sanitized

    def test_truncation(self) -> None:
        result = sanitize_text("a" * 100, max_length=50)
        assert len(result.sanitized) == 50
        assert result.truncated
        assert ThreatType.OVERSIZED in [t.threat_type for t in result.threats]

    def test_no_strip_html_option(self) -> None:
        result = sanitize_text("<b>bold</b>", strip_html=False)
        assert "<b>" in result.sanitized

    def test_clean_input_is_clean(self) -> None:
        result = sanitize_text("Hello, this is safe input!")
        assert result.is_clean

    def test_threats_logged(self) -> None:
        result = sanitize_text("' UNION SELECT 1--")
        assert not result.is_clean


class TestStripFunctions:
    def test_strip_null_bytes(self) -> None:
        assert strip_null_bytes("abc\x00def") == "abcdef"

    def test_strip_html_tags(self) -> None:
        assert strip_html_tags("<p>Hello <b>world</b></p>") == "Hello world"

    def test_strip_html_noop_on_clean(self) -> None:
        assert strip_html_tags("plain text") == "plain text"


class TestSanitizeFilename:
    def test_path_traversal_blocked(self) -> None:
        safe = sanitize_filename("../../etc/passwd")
        assert ".." not in safe
        assert "/" not in safe

    def test_removes_leading_dot(self) -> None:
        safe = sanitize_filename(".hidden")
        assert not safe.startswith(".")

    def test_keeps_valid_name(self) -> None:
        safe = sanitize_filename("report_2024.pdf")
        assert safe == "report_2024.pdf"

    def test_empty_string_safe(self) -> None:
        safe = sanitize_filename("")
        assert safe == "_"

    def test_null_byte_removed(self) -> None:
        safe = sanitize_filename("file\x00.txt")
        assert "\x00" not in safe

    def test_special_chars_replaced(self) -> None:
        safe = sanitize_filename("file name;here.txt")
        assert ";" not in safe
        assert " " not in safe


class TestValidateEmail:
    def test_valid(self) -> None:
        assert validate_email("user@example.com")

    def test_valid_with_plus(self) -> None:
        assert validate_email("user+tag@sub.domain.com")

    def test_missing_at(self) -> None:
        assert not validate_email("userexample.com")

    def test_missing_domain(self) -> None:
        assert not validate_email("user@")

    def test_too_long(self) -> None:
        assert not validate_email("a" * 250 + "@example.com")


class TestValidateInteger:
    def test_valid_integer(self) -> None:
        assert validate_integer("42") == 42

    def test_negative(self) -> None:
        assert validate_integer("-5") == -5

    def test_not_integer(self) -> None:
        with pytest.raises(ValueError):
            validate_integer("abc")

    def test_float_rejected(self) -> None:
        with pytest.raises(ValueError):
            validate_integer("3.14")

    def test_below_min(self) -> None:
        with pytest.raises(ValueError):
            validate_integer("0", min_val=1)

    def test_above_max(self) -> None:
        with pytest.raises(ValueError):
            validate_integer("100", max_val=50)

    def test_in_range(self) -> None:
        assert validate_integer("25", min_val=0, max_val=100) == 25
