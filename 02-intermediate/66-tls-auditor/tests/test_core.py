"""Tests for project 66 TLS Auditor."""

from __future__ import annotations

import datetime

from project_66.core import (
    CERT_CRITICAL_DAYS,
    CERT_WARN_DAYS,
    CertInfo,
    CipherInfo,
    TLSAuditResult,
    _analyse_cert,
    _analyse_cipher,
    _analyse_protocol,
    analyse_result,
    audit_tls,
)

# ---------------------------------------------------------------------------
# CipherInfo
# ---------------------------------------------------------------------------

class TestCipherInfo:
    def test_strong_cipher_not_weak(self) -> None:
        c = CipherInfo(name="TLS_AES_256_GCM_SHA384", protocol="TLSv1.3", bits=256)
        assert not c.is_weak

    def test_rc4_is_weak(self) -> None:
        c = CipherInfo(name="RC4-SHA", protocol="TLSv1.2", bits=128)
        assert c.is_weak

    def test_null_cipher_is_weak(self) -> None:
        c = CipherInfo(name="NULL-SHA", protocol="TLSv1.2", bits=0)
        assert c.is_weak

    def test_des_is_weak(self) -> None:
        c = CipherInfo(name="DES-CBC3-SHA", protocol="TLSv1.2", bits=112)
        assert c.is_weak


# ---------------------------------------------------------------------------
# CertInfo
# ---------------------------------------------------------------------------

def _make_cert(days_remaining: int, sig_algo: str = "sha256WithRSAEncryption") -> CertInfo:
    now = datetime.datetime.now(tz=datetime.UTC)
    return CertInfo(
        subject={"commonName": "example.com"},
        issuer={"organizationName": "Test CA"},
        not_before=now - datetime.timedelta(days=365),
        not_after=now + datetime.timedelta(days=days_remaining),
        san=["DNS:example.com"],
        serial_number="DEADBEEF",
        signature_algorithm=sig_algo,
    )


class TestCertInfo:
    def test_valid_cert_ok(self) -> None:
        cert = _make_cert(90)
        assert cert.expiry_severity == "ok"
        assert not cert.is_expired
        assert cert.days_until_expiry > 0

    def test_warning_range(self) -> None:
        cert = _make_cert(CERT_WARN_DAYS - 1)
        assert cert.expiry_severity == "warning"

    def test_critical_range(self) -> None:
        cert = _make_cert(CERT_CRITICAL_DAYS - 1)
        assert cert.expiry_severity == "critical"

    def test_expired(self) -> None:
        cert = _make_cert(-1)
        assert cert.is_expired
        assert cert.expiry_severity == "expired"


# ---------------------------------------------------------------------------
# TLSAuditResult
# ---------------------------------------------------------------------------

class TestTLSAuditResult:
    def test_initial_score_100(self) -> None:
        r = TLSAuditResult(host="x", port=443)
        assert r.score == 100

    def test_add_finding_deducts_score(self) -> None:
        r = TLSAuditResult(host="x", port=443)
        r.add_finding("critical", "bad thing", deduction=20)
        assert r.score == 80
        assert any("bad thing" in f for f in r.findings)

    def test_score_floor_zero(self) -> None:
        r = TLSAuditResult(host="x", port=443)
        r.add_finding("critical", "bad", deduction=200)
        assert r.score == 0

    def test_grade_a(self) -> None:
        r = TLSAuditResult(host="x", port=443)
        assert r.grade == "A"

    def test_grade_f(self) -> None:
        r = TLSAuditResult(host="x", port=443)
        r.add_finding("critical", "bad", deduction=200)
        assert r.grade == "F"


# ---------------------------------------------------------------------------
# _analyse_protocol
# ---------------------------------------------------------------------------

class TestAnalyseProtocol:
    def test_weak_protocol_deduction(self) -> None:
        r = TLSAuditResult(host="x", port=443, protocol_version="TLSv1")
        _analyse_protocol(r)
        assert r.score < 100
        assert any("TLSv1" in f for f in r.findings)

    def test_tlsv12_no_finding(self) -> None:
        r = TLSAuditResult(host="x", port=443, protocol_version="TLSv1.2")
        _analyse_protocol(r)
        assert r.score == 100

    def test_tlsv13_no_finding(self) -> None:
        r = TLSAuditResult(host="x", port=443, protocol_version="TLSv1.3")
        _analyse_protocol(r)
        assert r.score == 100


# ---------------------------------------------------------------------------
# _analyse_cipher
# ---------------------------------------------------------------------------

class TestAnalyseCipher:
    def test_no_cipher_no_crash(self) -> None:
        r = TLSAuditResult(host="x", port=443)
        _analyse_cipher(r)  # should not raise

    def test_weak_cipher_finding(self) -> None:
        r = TLSAuditResult(host="x", port=443, cipher=CipherInfo("RC4-MD5", "TLSv1.2", 128))
        _analyse_cipher(r)
        assert r.score < 100

    def test_strong_cipher_no_critical(self) -> None:
        r = TLSAuditResult(host="x", port=443, cipher=CipherInfo("AES_256_GCM_SHA384", "TLSv1.3", 256))
        _analyse_cipher(r)
        assert not any("CRITICAL" in f for f in r.findings)

    def test_short_key_finding(self) -> None:
        r = TLSAuditResult(host="x", port=443, cipher=CipherInfo("DES-CBC", "TLSv1.2", 56))
        _analyse_cipher(r)
        assert any("key length" in f.lower() or "bits" in f.lower() for f in r.findings)


# ---------------------------------------------------------------------------
# _analyse_cert
# ---------------------------------------------------------------------------

class TestAnalyseCert:
    def test_no_cert_critical(self) -> None:
        r = TLSAuditResult(host="x", port=443)
        _analyse_cert(r)
        assert r.score < 100

    def test_expired_cert_finding(self) -> None:
        r = TLSAuditResult(host="x", port=443, cert=_make_cert(-10))
        _analyse_cert(r)
        assert any("EXPIRED" in f.upper() for f in r.findings)

    def test_sha1_finding(self) -> None:
        r = TLSAuditResult(host="x", port=443, cert=_make_cert(90, "sha1WithRSAEncryption"))
        _analyse_cert(r)
        assert any("sha1" in f.lower() for f in r.findings)

    def test_no_san_warning(self) -> None:
        now = datetime.datetime.now(tz=datetime.UTC)
        cert = CertInfo(
            subject={"commonName": "x"}, issuer={},
            not_before=now - datetime.timedelta(days=1),
            not_after=now + datetime.timedelta(days=90),
            san=[], serial_number="1", signature_algorithm="sha256WithRSAEncryption",
        )
        r = TLSAuditResult(host="x", port=443, cert=cert)
        _analyse_cert(r)
        assert any("SAN" in f for f in r.findings)


# ---------------------------------------------------------------------------
# analyse_result
# ---------------------------------------------------------------------------

class TestAnalyseResult:
    def test_summary_keys(self) -> None:
        r = TLSAuditResult(host="example.com", port=443, connected=True, protocol_version="TLSv1.3")
        r.cipher = CipherInfo("AES_256_GCM_SHA384", "TLSv1.3", 256)
        summary = analyse_result(r)
        assert summary["host"] == "example.com"
        assert "grade" in summary
        assert "score" in summary
        assert "cipher" in summary

    def test_cert_in_summary(self) -> None:
        r = TLSAuditResult(host="x", port=443, connected=True, cert=_make_cert(90))
        summary = analyse_result(r)
        assert "certificate" in summary
        assert summary["certificate"]["days_remaining"] > 0  # type: ignore[index]


# ---------------------------------------------------------------------------
# audit_tls (connection failure path)
# ---------------------------------------------------------------------------

class TestAuditTLS:
    def test_connection_failure_returns_result(self) -> None:
        # Port 1 on localhost is not open — expect graceful failure
        result = audit_tls("127.0.0.1", port=1, timeout=2)
        assert not result.connected
        assert result.findings  # at least one info finding
