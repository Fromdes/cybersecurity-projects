"""Tests for project_19.cli — IP Geolocation & ASN Lookup CLI."""
from __future__ import annotations

import json
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from project_19.cli import main
from project_19.core import GeoResult

_SAMPLE = GeoResult(
    ip="8.8.8.8",
    country="United States",
    country_code="US",
    region="California",
    city="Mountain View",
    latitude=37.3861,
    longitude=-122.0839,
    isp="Google LLC",
    org="AS15169 Google LLC",
    asn="AS15169 Google LLC",
    timezone="America/Los_Angeles",
    is_proxy=False,
    is_hosting=True,
)


class TestSingleLookup:
    @patch("project_19.cli.lookup_ip")
    def test_human_output(self, mock_lookup: MagicMock, capsys: pytest.CaptureFixture) -> None:
        mock_lookup.return_value = _SAMPLE
        with patch("sys.argv", ["ip-geo", "8.8.8.8"]):
            main()
        out = capsys.readouterr().out
        assert "8.8.8.8" in out
        assert "United States" in out

    @patch("project_19.cli.lookup_ip")
    def test_json_output(self, mock_lookup: MagicMock, capsys: pytest.CaptureFixture) -> None:
        mock_lookup.return_value = _SAMPLE
        with patch("sys.argv", ["ip-geo", "--json", "8.8.8.8"]):
            main()
        out = capsys.readouterr().out
        data = json.loads(out)
        assert data["ip"] == "8.8.8.8"

    @patch("project_19.cli.lookup_ip")
    def test_hosting_flag_shown(self, mock_lookup: MagicMock, capsys: pytest.CaptureFixture) -> None:
        mock_lookup.return_value = _SAMPLE
        with patch("sys.argv", ["ip-geo", "8.8.8.8"]):
            main()
        out = capsys.readouterr().out
        assert "HOSTING" in out

    def test_invalid_ip_exits(self, capsys: pytest.CaptureFixture) -> None:
        with pytest.raises(SystemExit) as exc_info:
            with patch("sys.argv", ["ip-geo", "not-an-ip"]):
                main()
        assert exc_info.value.code != 0


class TestFileLookup:
    @patch("project_19.cli.lookup_ip")
    def test_bulk_file(self, mock_lookup: MagicMock, capsys: pytest.CaptureFixture) -> None:
        mock_lookup.return_value = _SAMPLE
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("8.8.8.8\n1.1.1.1\n")
            fname = f.name
        with patch("sys.argv", ["ip-geo", "--file", fname]):
            main()
        out = capsys.readouterr().out
        assert out.count("8.8.8.8") >= 1
