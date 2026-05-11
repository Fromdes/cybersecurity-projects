"""Unit tests for project_07.core — all network calls are mocked."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from project_07.core import (
    K_ANON_PREFIX_LEN,
    check_hash,
    check_password,
    hash_password,
    query_range,
)

# SHA-1 of "password" — well-known value for testing
_SHA1_OF_PASSWORD = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
_PREFIX = _SHA1_OF_PASSWORD[:K_ANON_PREFIX_LEN]   # "5BAA6"
_SUFFIX = _SHA1_OF_PASSWORD[K_ANON_PREFIX_LEN:]   # "1E4C9B93F3F0682250B6CF8331B7EE68FD8"


def _make_mock_session(response_text: str, status_code: int = 200) -> MagicMock:
    mock_response = MagicMock()
    mock_response.status_code = status_code
    mock_response.text = response_text
    mock_response.raise_for_status = MagicMock()
    mock_session = MagicMock()
    mock_session.get.return_value = mock_response
    return mock_session


class TestHashPassword:
    def test_known_value(self) -> None:
        assert hash_password("password") == _SHA1_OF_PASSWORD

    def test_empty_string(self) -> None:
        result = hash_password("")
        assert len(result) == 40
        assert result == result.upper()

    def test_unicode(self) -> None:
        result = hash_password("pässwørd")
        assert len(result) == 40


class TestQueryRange:
    def test_returns_parsed_dict(self) -> None:
        fake_body = f"{_SUFFIX}:12345\nABCDEF1234567890ABCDEF1234567890ABC:99\n"
        session = _make_mock_session(fake_body)
        result = query_range(_PREFIX, session)
        assert result[_SUFFIX] == 12345
        assert result.get("ABCDEF1234567890ABCDEF1234567890ABC") == 99

    def test_http_error_raised(self) -> None:
        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = requests.HTTPError("404")
        session = MagicMock()
        session.get.return_value = mock_response
        with pytest.raises(requests.HTTPError):
            query_range(_PREFIX, session)

    def test_malformed_lines_ignored(self) -> None:
        fake_body = "BADLINE\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:5\n"
        session = _make_mock_session(fake_body)
        result = query_range(_PREFIX, session)
        assert isinstance(result, dict)


class TestCheckPassword:
    def test_pwned_password(self) -> None:
        fake_body = f"{_SUFFIX}:5000000\n"
        session = _make_mock_session(fake_body)
        count = check_password("password", session)
        assert count == 5_000_000

    def test_safe_password(self) -> None:
        session = _make_mock_session("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1\n")
        count = check_password("ThisIsAVeryUniquePassword!9xR#", session)
        assert count == 0

    def test_network_error_propagates(self) -> None:
        session = MagicMock()
        session.get.side_effect = requests.ConnectionError("no network")
        with pytest.raises(requests.ConnectionError):
            check_password("test", session)


class TestCheckHash:
    def test_valid_hash_pwned(self) -> None:
        fake_body = f"{_SUFFIX}:9876\n"
        session = _make_mock_session(fake_body)
        count = check_hash(_SHA1_OF_PASSWORD, session)
        assert count == 9876

    def test_invalid_hash_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid SHA-1"):
            check_hash("notahash", MagicMock())

    def test_short_hash_raises(self) -> None:
        with pytest.raises(ValueError):
            check_hash("5BAA6", MagicMock())

    def test_case_insensitive(self) -> None:
        fake_body = f"{_SUFFIX}:100\n"
        session = _make_mock_session(fake_body)
        count = check_hash(_SHA1_OF_PASSWORD.lower(), session)
        assert count == 100
