"""Tests for project_20.core — WHOIS Lookup Wrapper."""
from __future__ import annotations

from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from project_20.core import WhoisResult, _first_date, _list_of_str, _str_or_empty, lookup


def _make_whois_data(**kwargs: object) -> MagicMock:
    data = MagicMock()
    defaults = {
        "registrar": "Example Registrar LLC",
        "creation_date": datetime(2010, 1, 1),
        "expiration_date": datetime(2030, 1, 1),
        "updated_date": datetime(2023, 6, 15),
        "name_servers": ["NS1.EXAMPLE.COM", "NS2.EXAMPLE.COM"],
        "status": ["clientDeleteProhibited"],
        "emails": ["abuse@example.com"],
        "country": "US",
        "dnssec": "unsigned",
    }
    for key, val in {**defaults, **kwargs}.items():
        setattr(data, key, val)
    return data


class TestLookup:
    @patch("project_20.core.whois.whois")
    def test_returns_whois_result(self, mock_whois: MagicMock) -> None:
        mock_whois.return_value = _make_whois_data()
        result = lookup("example.com")
        assert isinstance(result, WhoisResult)
        assert result.query == "example.com"

    @patch("project_20.core.whois.whois")
    def test_registrar_populated(self, mock_whois: MagicMock) -> None:
        mock_whois.return_value = _make_whois_data()
        result = lookup("example.com")
        assert result.registrar == "Example Registrar LLC"

    @patch("project_20.core.whois.whois")
    def test_name_servers_lowercase(self, mock_whois: MagicMock) -> None:
        mock_whois.return_value = _make_whois_data(
            name_servers=["NS1.EXAMPLE.COM", "NS2.EXAMPLE.COM"]
        )
        result = lookup("example.com")
        assert all(ns == ns.lower() for ns in result.name_servers)

    @patch("project_20.core.whois.whois")
    def test_list_dates_takes_first(self, mock_whois: MagicMock) -> None:
        dt1 = datetime(2010, 1, 1)
        dt2 = datetime(2011, 1, 1)
        mock_whois.return_value = _make_whois_data(creation_date=[dt1, dt2])
        result = lookup("example.com")
        assert result.creation_date == dt1

    def test_empty_query_raises(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            lookup("")

    def test_whitespace_query_raises(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            lookup("   ")


class TestHelpers:
    def test_str_or_empty_none(self) -> None:
        assert _str_or_empty(None) == ""

    def test_str_or_empty_value(self) -> None:
        assert _str_or_empty("hello") == "hello"

    def test_first_date_list(self) -> None:
        dt = datetime(2020, 1, 1)
        assert _first_date([dt, datetime(2021, 1, 1)]) == dt

    def test_first_date_single(self) -> None:
        dt = datetime(2020, 1, 1)
        assert _first_date(dt) == dt

    def test_first_date_empty_list(self) -> None:
        assert _first_date([]) is None

    def test_first_date_none(self) -> None:
        assert _first_date(None) is None

    def test_list_of_str_list(self) -> None:
        assert _list_of_str(["a", "b"]) == ["a", "b"]

    def test_list_of_str_single(self) -> None:
        assert _list_of_str("single") == ["single"]

    def test_list_of_str_none(self) -> None:
        assert _list_of_str(None) == []
