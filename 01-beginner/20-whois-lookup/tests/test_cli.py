"""Tests for project_20.cli — WHOIS Lookup Wrapper CLI."""
from __future__ import annotations

import json
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from project_20.cli import main
from project_20.core import WhoisResult

_SAMPLE = WhoisResult(
    query="example.com",
    registrar="Example Registrar LLC",
    creation_date=datetime(1995, 8, 14),
    expiration_date=datetime(2024, 8, 13),
    updated_date=datetime(2023, 8, 14),
    name_servers=("ns1.example.com", "ns2.example.com"),
    status=("clientDeleteProhibited",),
    emails=("abuse@example.com",),
    country="US",
    dnssec="unsigned",
)


class TestMain:
    @patch("project_20.cli.lookup")
    def test_human_output(self, mock_lookup: MagicMock, capsys: pytest.CaptureFixture) -> None:
        mock_lookup.return_value = _SAMPLE
        with patch("sys.argv", ["whois-lookup", "example.com"]):
            main()
        out = capsys.readouterr().out
        assert "example.com" in out
        assert "Example Registrar LLC" in out

    @patch("project_20.cli.lookup")
    def test_json_output(self, mock_lookup: MagicMock, capsys: pytest.CaptureFixture) -> None:
        mock_lookup.return_value = _SAMPLE
        with patch("sys.argv", ["whois-lookup", "--json", "example.com"]):
            main()
        out = capsys.readouterr().out
        data = json.loads(out)
        assert data["query"] == "example.com"
        assert data["registrar"] == "Example Registrar LLC"

    @patch("project_20.cli.lookup")
    def test_name_servers_in_output(self, mock_lookup: MagicMock, capsys: pytest.CaptureFixture) -> None:
        mock_lookup.return_value = _SAMPLE
        with patch("sys.argv", ["whois-lookup", "example.com"]):
            main()
        out = capsys.readouterr().out
        assert "ns1.example.com" in out

    @patch("project_20.cli.lookup")
    def test_lookup_error_exits(self, mock_lookup: MagicMock, capsys: pytest.CaptureFixture) -> None:
        mock_lookup.side_effect = Exception("WHOIS timeout")
        with pytest.raises(SystemExit) as exc_info:
            with patch("sys.argv", ["whois-lookup", "bad.example"]):
                main()
        assert exc_info.value.code == 1

    @patch("project_20.cli.lookup")
    def test_dates_formatted(self, mock_lookup: MagicMock, capsys: pytest.CaptureFixture) -> None:
        mock_lookup.return_value = _SAMPLE
        with patch("sys.argv", ["whois-lookup", "example.com"]):
            main()
        out = capsys.readouterr().out
        assert "1995-08-14" in out
