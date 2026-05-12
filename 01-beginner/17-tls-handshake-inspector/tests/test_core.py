"""Tests for project_17.core — TLS Handshake Inspector."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from project_17.core import (
    TLSResult,
    _extract_san,
    _parse_cert,
    _parse_date,
    _rdn_to_dict,
    inspect_host,
)

CERT_DATE_FMT = "%b %d %H:%M:%S %Y %Z"
FUTURE_DATE = "Dec 31 23:59:59 2099 GMT"
PAST_DATE = "Jan 01 00:00:01 2000 GMT"


class TestParseCert:
    def test_parses_subject(self) -> None:
        raw = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("organizationName", "Let's Encrypt"),),),
            "notBefore": PAST_DATE,
            "notAfter": FUTURE_DATE,
            "serialNumber": "ABCD",
            "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
        }
        cert = _parse_cert(raw)
        assert cert.subject["commonName"] == "example.com"
        assert cert.issuer["organizationName"] == "Let's Encrypt"
        assert not cert.is_expired
        assert cert.days_until_expiry > 0

    def test_expired_cert(self) -> None:
        raw = {
            "subject": ((("commonName", "old.example.com"),),),
            "issuer": (),
            "notBefore": PAST_DATE,
            "notAfter": PAST_DATE,
            "serialNumber": "1",
            "subjectAltName": (),
        }
        cert = _parse_cert(raw)
        assert cert.is_expired

    def test_san_extraction(self) -> None:
        raw = {
            "subject": (), "issuer": (),
            "notBefore": PAST_DATE, "notAfter": FUTURE_DATE,
            "serialNumber": "", "subjectAltName": (("DNS", "a.com"), ("IP", "1.2.3.4")),
        }
        cert = _parse_cert(raw)
        assert "DNS:a.com" in cert.san
        assert "IP:1.2.3.4" in cert.san


class TestHelpers:
    def test_rdn_to_dict(self) -> None:
        rdn = ((("commonName", "test.com"),), (("countryName", "US"),))
        result = _rdn_to_dict(rdn)
        assert result["commonName"] == "test.com"
        assert result["countryName"] == "US"

    def test_parse_date_valid(self) -> None:
        dt = _parse_date("Jan 01 00:00:01 2030 GMT")
        assert dt is not None
        assert dt.year == 2030

    def test_parse_date_empty(self) -> None:
        assert _parse_date("") is None

    def test_parse_date_invalid(self) -> None:
        assert _parse_date("not-a-date") is None

    def test_extract_san(self) -> None:
        san = (("DNS", "example.com"), ("IP Address", "192.168.1.1"))
        result = _extract_san(san)
        assert "DNS:example.com" in result


class TestInspectHost:
    def test_empty_host_raises(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            inspect_host("")

    def test_whitespace_host_raises(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            inspect_host("   ")

    @patch("project_17.core.socket.create_connection")
    @patch("project_17.core.ssl.create_default_context")
    def test_inspect_success(self, mock_ctx: MagicMock, mock_conn: MagicMock) -> None:
        mock_ssl_sock = MagicMock()
        mock_ssl_sock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_ssl_sock.version.return_value = "TLSv1.3"
        mock_ssl_sock.getpeercert.return_value = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("organizationName", "TestCA"),),),
            "notBefore": PAST_DATE,
            "notAfter": FUTURE_DATE,
            "serialNumber": "FF",
            "subjectAltName": (("DNS", "example.com"),),
        }
        mock_ctx.return_value.wrap_socket.return_value.__enter__.return_value = mock_ssl_sock
        mock_conn.return_value.__enter__.return_value = MagicMock()

        result = inspect_host("example.com")
        assert isinstance(result, TLSResult)
        assert result.host == "example.com"
