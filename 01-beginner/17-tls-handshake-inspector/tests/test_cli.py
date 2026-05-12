"""Tests for project_17.cli — TLS Handshake Inspector CLI."""
from __future__ import annotations

import json
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest

from project_17.cli import _print_human, _result_to_dict, main
from project_17.core import CertInfo, TLSResult

_PAST = datetime(2000, 1, 1, tzinfo=UTC)
_FUTURE = datetime(2099, 12, 31, tzinfo=UTC)


def _make_result(expired: bool = False) -> TLSResult:
    cert = CertInfo(
        subject={"commonName": "example.com"},
        issuer={"organizationName": "TestCA"},
        serial_number="ABCD",
        not_before=_PAST,
        not_after=_PAST if expired else _FUTURE,
        san=["DNS:example.com"],
        is_expired=expired,
        days_until_expiry=-1 if expired else 36524,
    )
    return TLSResult(
        host="example.com", port=443,
        protocol_version="TLSv1.3",
        cipher_name="TLS_AES_256_GCM_SHA384",
        cipher_bits=256,
        cert=cert, tls_ok=not expired,
    )


class TestResultToDict:
    def test_keys_present(self) -> None:
        d = _result_to_dict(_make_result())
        assert "host" in d
        assert "certificate" in d
        assert "protocol_version" in d

    def test_cert_dates_are_iso(self) -> None:
        d = _result_to_dict(_make_result())
        cert = d["certificate"]
        assert "T" in cert["not_before"]  # ISO format contains T


class TestPrintHuman:
    def test_prints_host(self, capsys: pytest.CaptureFixture) -> None:
        _print_human(_make_result())
        out = capsys.readouterr().out
        assert "example.com" in out
        assert "TLSv1.3" in out
        assert "TLS_AES_256_GCM_SHA384" in out

    def test_expired_shows_expired(self, capsys: pytest.CaptureFixture) -> None:
        _print_human(_make_result(expired=True))
        out = capsys.readouterr().out
        assert "EXPIRED" in out


class TestMain:
    @patch("project_17.cli.inspect_host")
    def test_json_output(self, mock_inspect: MagicMock, capsys: pytest.CaptureFixture) -> None:
        mock_inspect.return_value = _make_result()
        with patch("sys.argv", ["tls-inspect", "--json", "example.com"]):
            main()
        out = capsys.readouterr().out
        data = json.loads(out)
        assert data["host"] == "example.com"

    @patch("project_17.cli.inspect_host")
    def test_human_output(self, mock_inspect: MagicMock, capsys: pytest.CaptureFixture) -> None:
        mock_inspect.return_value = _make_result()
        with patch("sys.argv", ["tls-inspect", "example.com"]):
            main()
        out = capsys.readouterr().out
        assert "example.com" in out

    def test_os_error_exits(self, capsys: pytest.CaptureFixture) -> None:
        with patch("project_17.cli.inspect_host", side_effect=OSError("connection refused")):
            with patch("sys.argv", ["tls-inspect", "bad.host"]):
                with pytest.raises(SystemExit) as exc_info:
                    main()
        assert exc_info.value.code == 1
