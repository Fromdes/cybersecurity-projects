"""Tests for project_19.core — IP Geolocation & ASN Lookup."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from project_19.core import GeoResult, lookup_ip


def _mock_response(data: dict) -> MagicMock:
    mock = MagicMock()
    mock.json.return_value = data
    mock.raise_for_status = MagicMock()
    return mock


SUCCESS_PAYLOAD: dict = {
    "status": "success",
    "query": "8.8.8.8",
    "country": "United States",
    "countryCode": "US",
    "regionName": "California",
    "city": "Mountain View",
    "lat": 37.3861,
    "lon": -122.0839,
    "isp": "Google LLC",
    "org": "AS15169 Google LLC",
    "as": "AS15169 Google LLC",
    "timezone": "America/Los_Angeles",
    "proxy": False,
    "hosting": True,
}


class TestLookupIP:
    @patch("project_19.core.requests.get")
    def test_success_returns_geo_result(self, mock_get: MagicMock) -> None:
        mock_get.return_value = _mock_response(SUCCESS_PAYLOAD)

        result = lookup_ip("8.8.8.8")

        assert isinstance(result, GeoResult)
        assert result.ip == "8.8.8.8"
        assert result.country == "United States"
        assert result.country_code == "US"

    @patch("project_19.core.requests.get")
    def test_asn_populated(self, mock_get: MagicMock) -> None:
        mock_get.return_value = _mock_response(SUCCESS_PAYLOAD)
        result = lookup_ip("8.8.8.8")
        assert "AS15169" in result.asn

    @patch("project_19.core.requests.get")
    def test_proxy_flag(self, mock_get: MagicMock) -> None:
        payload = {**SUCCESS_PAYLOAD, "proxy": True}
        mock_get.return_value = _mock_response(payload)
        result = lookup_ip("8.8.8.8")
        assert result.is_proxy is True

    @patch("project_19.core.requests.get")
    def test_api_failure_raises(self, mock_get: MagicMock) -> None:
        payload = {"status": "fail", "message": "private range"}
        mock_get.return_value = _mock_response(payload)
        with pytest.raises(RuntimeError, match="API error"):
            lookup_ip("192.168.1.1")

    def test_invalid_ip_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid IP"):
            lookup_ip("not-an-ip")

    @patch("project_19.core.requests.get")
    def test_me_sentinel_skips_validation(self, mock_get: MagicMock) -> None:
        mock_get.return_value = _mock_response(SUCCESS_PAYLOAD)
        result = lookup_ip("me")
        assert isinstance(result, GeoResult)

    @patch("project_19.core.requests.get")
    def test_http_error_propagates(self, mock_get: MagicMock) -> None:
        mock_get.return_value.raise_for_status.side_effect = (
            requests.HTTPError("429 Too Many Requests")
        )
        with pytest.raises(requests.HTTPError):
            lookup_ip("1.1.1.1")
