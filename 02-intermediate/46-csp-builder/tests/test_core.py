"""Tests for project 46 core module."""

from __future__ import annotations

import json

import pytest

from project_46.core import (
    CSPBuilder,
    CSPPolicy,
    CSPViolationReport,
    FetchDirective,
    OtherDirective,
    is_valid_source_value,
    parse_policy,
)

NONE_VALUE = "'none'"
SELF_VALUE = "'self'"


class TestCSPPolicy:
    def test_set_replaces_values(self) -> None:
        p = CSPPolicy()
        p.set("script-src", SELF_VALUE)
        p.set("script-src", NONE_VALUE)
        assert p.directives["script-src"] == [NONE_VALUE]

    def test_add_appends_unique(self) -> None:
        p = CSPPolicy()
        p.add("img-src", SELF_VALUE)
        p.add("img-src", SELF_VALUE)
        assert p.directives["img-src"] == [SELF_VALUE]

    def test_remove_directive(self) -> None:
        p = CSPPolicy()
        p.set("object-src", NONE_VALUE)
        p.remove("object-src")
        assert "object-src" not in p.directives

    def test_build_serialises_correctly(self) -> None:
        p = CSPPolicy()
        p.set("default-src", NONE_VALUE)
        p.set("upgrade-insecure-requests")
        header = p.build()
        assert "default-src 'none'" in header
        assert "upgrade-insecure-requests" in header


class TestCSPBuilder:
    def test_strict_contains_object_src_none(self) -> None:
        policy = CSPBuilder().strict().build()
        assert policy.directives.get(FetchDirective.OBJECT_SRC.value) == [NONE_VALUE]

    def test_add_nonce(self) -> None:
        builder = CSPBuilder().strict()
        builder.allow_nonce("script-src", "abc123==")
        policy = builder.build()
        assert "'nonce-abc123=='" in policy.directives["script-src"]

    def test_add_hash(self) -> None:
        builder = CSPBuilder().strict()
        builder.allow_hash("script-src", "sha256", "xyz==")
        policy = builder.build()
        assert "'sha256-xyz=='" in policy.directives["script-src"]

    def test_report_only(self) -> None:
        policy = CSPBuilder().strict().report_only("/csp-report").build()
        assert policy.directives.get("report-uri") == ["/csp-report"]

    def test_header_value_is_string(self) -> None:
        val = CSPBuilder().strict().header_value()
        assert isinstance(val, str)
        assert len(val) > 10


class TestAnalyse:
    def test_detects_unsafe_inline(self) -> None:
        p = CSPPolicy()
        p.set("script-src", "'unsafe-inline'")
        warnings = p.analyse()
        high = [w for w in warnings if w.severity == "high"]
        assert any("unsafe-inline" in w.message for w in high)

    def test_detects_unsafe_eval(self) -> None:
        p = CSPPolicy()
        p.set("script-src", "'unsafe-eval'")
        warnings = p.analyse()
        assert any("eval" in w.message for w in warnings)

    def test_detects_wildcard(self) -> None:
        p = CSPPolicy()
        p.set("default-src", "*")
        warnings = p.analyse()
        assert any("Wildcard" in w.message for w in warnings)

    def test_no_warnings_on_strict(self) -> None:
        policy = CSPBuilder().strict().build()
        warnings = policy.analyse()
        assert len(warnings) == 0


class TestParsePolicy:
    def test_roundtrip(self) -> None:
        original = "default-src 'none'; script-src 'self'; object-src 'none'"
        policy = parse_policy(original)
        assert policy.directives["default-src"] == ["'none'"]
        assert policy.directives["script-src"] == ["'self'"]

    def test_empty_string(self) -> None:
        policy = parse_policy("")
        assert policy.directives == {}


class TestViolationReport:
    def test_from_json_dict(self) -> None:
        raw: dict = {
            "csp-report": {
                "document-uri": "https://example.com/page",
                "violated-directive": "script-src",
                "effective-directive": "script-src",
                "blocked-uri": "https://evil.com/x.js",
                "original-policy": "script-src 'self'",
                "status-code": 200,
            }
        }
        report = CSPViolationReport.from_json(raw)
        assert report.blocked_uri == "https://evil.com/x.js"
        assert report.status_code == 200

    def test_from_json_string(self) -> None:
        data = {"document-uri": "https://x.com", "violated-directive": "img-src",
                "effective-directive": "img-src", "blocked-uri": "data:", "original-policy": ""}
        report = CSPViolationReport.from_json(json.dumps(data))
        assert report.document_uri == "https://x.com"


class TestIsValidSourceValue:
    def test_self_valid(self) -> None:
        assert is_valid_source_value("'self'")

    def test_none_valid(self) -> None:
        assert is_valid_source_value("'none'")

    def test_nonce_valid(self) -> None:
        assert is_valid_source_value("'nonce-abc123=='")

    def test_hash_valid(self) -> None:
        assert is_valid_source_value("'sha256-abc123=='")

    def test_scheme_valid(self) -> None:
        assert is_valid_source_value("https:")

    def test_host_valid(self) -> None:
        assert is_valid_source_value("cdn.example.com")

    def test_wildcard_valid(self) -> None:
        assert is_valid_source_value("*")

    def test_invalid(self) -> None:
        assert not is_valid_source_value("!!!bad!!!")
