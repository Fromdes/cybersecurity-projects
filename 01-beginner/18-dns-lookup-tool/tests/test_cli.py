"""Tests for project_18.cli — DNS Lookup & Reverse DNS CLI."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import dns.exception
import pytest

from project_18.cli import main
from project_18.core import DNSRecord, RecordType


def _record(value: str) -> DNSRecord:
    return DNSRecord(name="example.com.", record_type=RecordType.A, ttl=300, value=value)


class TestLookupCommand:
    @patch("project_18.cli.lookup")
    def test_prints_records(self, mock_lookup: MagicMock, capsys: pytest.CaptureFixture) -> None:
        mock_lookup.return_value = [_record("93.184.216.34")]
        with patch("sys.argv", ["dns-lookup", "lookup", "example.com"]):
            main()
        out = capsys.readouterr().out
        assert "93.184.216.34" in out

    @patch("project_18.cli.lookup")
    def test_empty_records(self, mock_lookup: MagicMock, capsys: pytest.CaptureFixture) -> None:
        mock_lookup.return_value = []
        with patch("sys.argv", ["dns-lookup", "lookup", "example.com"]):
            main()
        out = capsys.readouterr().out
        assert "No A records" in out

    @patch("project_18.cli.lookup")
    def test_dns_error_exits(self, mock_lookup: MagicMock, capsys: pytest.CaptureFixture) -> None:
        mock_lookup.side_effect = dns.exception.DNSException("NXDOMAIN")
        with pytest.raises(SystemExit) as exc_info:
            with patch("sys.argv", ["dns-lookup", "lookup", "bad.example.invalid"]):
                main()
        assert exc_info.value.code == 1


class TestReverseCommand:
    @patch("project_18.cli.reverse_lookup")
    def test_ptr_output(self, mock_rev: MagicMock, capsys: pytest.CaptureFixture) -> None:
        ptr = DNSRecord(
            name="8.8.8.8.in-addr.arpa.",
            record_type=RecordType.PTR,
            ttl=3600,
            value="dns.google.",
        )
        mock_rev.return_value = [ptr]
        with patch("sys.argv", ["dns-lookup", "reverse", "8.8.8.8"]):
            main()
        out = capsys.readouterr().out
        assert "dns.google." in out

    def test_invalid_ip_exits(self, capsys: pytest.CaptureFixture) -> None:
        with pytest.raises(SystemExit) as exc_info:
            with patch("sys.argv", ["dns-lookup", "reverse", "not-an-ip"]):
                main()
        assert exc_info.value.code == 1
