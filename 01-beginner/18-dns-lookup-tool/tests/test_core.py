"""Tests for project_18.core — DNS Lookup & Reverse DNS Tool."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import dns.exception
import dns.resolver
import pytest

from project_18.core import DNSRecord, RecordType, lookup, reverse_lookup


def _make_mock_answer(name: str, ttl: int, values: list[str]) -> MagicMock:
    mock_rrset = MagicMock()
    mock_rrset.ttl = ttl
    answer = MagicMock()
    answer.qname = name
    answer.rrset = mock_rrset
    answer.__iter__ = MagicMock(return_value=iter([MagicMock(__str__=lambda s: v) for v in values]))
    return answer


class TestLookup:
    def test_empty_hostname_raises(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            lookup("", RecordType.A)

    def test_whitespace_hostname_raises(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            lookup("   ", RecordType.A)

    @patch("project_18.core.dns.resolver.Resolver.resolve")
    def test_returns_records(self, mock_resolve: MagicMock) -> None:
        mock_rrset = MagicMock()
        mock_rrset.ttl = 300
        mock_answer = MagicMock()
        mock_answer.qname = "example.com."
        mock_answer.rrset = mock_rrset
        rdata = MagicMock()
        rdata.__str__.return_value = "93.184.216.34"
        mock_answer.__iter__ = MagicMock(return_value=iter([rdata]))
        mock_resolve.return_value = mock_answer

        records = lookup("example.com", RecordType.A)

        assert len(records) == 1
        assert isinstance(records[0], DNSRecord)
        assert records[0].record_type == RecordType.A

    @patch("project_18.core.dns.resolver.Resolver.resolve")
    def test_nxdomain_raises_dns_exception(self, mock_resolve: MagicMock) -> None:
        mock_resolve.side_effect = dns.resolver.NXDOMAIN
        with pytest.raises(dns.exception.DNSException, match="No such domain"):
            lookup("nonexistent.example.invalid", RecordType.A)

    @patch("project_18.core.dns.resolver.Resolver.resolve")
    def test_no_answer_raises_dns_exception(self, mock_resolve: MagicMock) -> None:
        mock_resolve.side_effect = dns.resolver.NoAnswer
        with pytest.raises(dns.exception.DNSException, match="No A records"):
            lookup("example.com", RecordType.A)


class TestReverseLookup:
    def test_invalid_ip_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid IP"):
            reverse_lookup("not-an-ip")

    def test_valid_ipv4_format(self) -> None:
        with patch("project_18.core.dns.resolver.Resolver.resolve") as mock_resolve:
            mock_rrset = MagicMock()
            mock_rrset.ttl = 3600
            mock_answer = MagicMock()
            mock_answer.rrset = mock_rrset
            rdata = MagicMock()
            rdata.__str__.return_value = "host.example.com."
            mock_answer.__iter__ = MagicMock(return_value=iter([rdata]))
            mock_resolve.return_value = mock_answer

            records = reverse_lookup("8.8.8.8")

            assert len(records) == 1
            assert records[0].record_type == RecordType.PTR

    @patch("project_18.core.dns.resolver.Resolver.resolve")
    def test_nxdomain_raises(self, mock_resolve: MagicMock) -> None:
        mock_resolve.side_effect = dns.resolver.NXDOMAIN
        with pytest.raises(dns.exception.DNSException, match="No PTR record"):
            reverse_lookup("10.0.0.1")
