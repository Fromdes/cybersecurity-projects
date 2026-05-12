"""Tests for project 67 Certificate Transparency Monitor."""

from __future__ import annotations

import datetime

import pytest

from project_67.core import (
    CTLogEntry,
    CTMonitorResult,
    _parse_dt,
    detect_anomalies,
    filter_entries,
    parse_crtsh_response,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_NOW = datetime.datetime.now(tz=datetime.UTC)
_FUTURE = _NOW + datetime.timedelta(days=90)
_PAST = _NOW - datetime.timedelta(days=1)


def _entry(
    id: int = 1,
    common_name: str = "example.com",
    name_value: str = "example.com",
    issuer: str = "Let's Encrypt",
    logged_at: datetime.datetime | None = None,
    not_after: datetime.datetime | None = None,
) -> CTLogEntry:
    return CTLogEntry(
        id=id,
        logged_at=logged_at or _NOW,
        not_before=_NOW - datetime.timedelta(days=30),
        not_after=not_after or _FUTURE,
        common_name=common_name,
        name_value=name_value,
        issuer_name=issuer,
        serial_number="DEAD",
    )


# ---------------------------------------------------------------------------
# _parse_dt
# ---------------------------------------------------------------------------

class TestParseDt:
    def test_iso_format(self) -> None:
        dt = _parse_dt("2024-01-15T10:30:00")
        assert dt.year == 2024
        assert dt.month == 1
        assert dt.tzinfo is not None

    def test_date_only(self) -> None:
        dt = _parse_dt("2024-06-01")
        assert dt.year == 2024

    def test_with_microseconds(self) -> None:
        dt = _parse_dt("2024-01-15T10:30:00.123456")
        assert dt.microsecond > 0

    def test_empty_raises(self) -> None:
        with pytest.raises(ValueError):
            _parse_dt("")

    def test_invalid_raises(self) -> None:
        with pytest.raises(ValueError):
            _parse_dt("not-a-date")


# ---------------------------------------------------------------------------
# CTLogEntry
# ---------------------------------------------------------------------------

class TestCTLogEntry:
    def test_domains_single(self) -> None:
        e = _entry(name_value="example.com")
        assert e.domains == ["example.com"]

    def test_domains_multiple(self) -> None:
        e = _entry(name_value="example.com\nwww.example.com")
        assert len(e.domains) == 2

    def test_wildcard_detected(self) -> None:
        e = _entry(name_value="*.example.com")
        assert e.is_wildcard

    def test_not_wildcard(self) -> None:
        e = _entry(name_value="example.com")
        assert not e.is_wildcard

    def test_expired(self) -> None:
        e = _entry(not_after=_PAST)
        assert e.is_expired

    def test_not_expired(self) -> None:
        e = _entry(not_after=_FUTURE)
        assert not e.is_expired

    def test_days_until_expiry_positive(self) -> None:
        e = _entry(not_after=_NOW + datetime.timedelta(days=30))
        assert e.days_until_expiry > 0


# ---------------------------------------------------------------------------
# parse_crtsh_response
# ---------------------------------------------------------------------------

class TestParseCrtshResponse:
    def _raw(self, id: int = 1, cn: str = "example.com") -> dict:  # type: ignore[type-arg]
        return {
            "id": id,
            "entry_timestamp": "2024-01-01T00:00:00",
            "not_before": "2024-01-01T00:00:00",
            "not_after": "2025-01-01T00:00:00",
            "common_name": cn,
            "name_value": cn,
            "issuer_name": "Test CA",
            "serial_number": "DEAD",
        }

    def test_single_entry(self) -> None:
        entries = parse_crtsh_response([self._raw()])
        assert len(entries) == 1
        assert entries[0].common_name == "example.com"

    def test_deduplication(self) -> None:
        # Same ID twice should yield one entry
        entries = parse_crtsh_response([self._raw(1), self._raw(1)])
        assert len(entries) == 1

    def test_multiple_entries(self) -> None:
        entries = parse_crtsh_response([self._raw(1, "a.com"), self._raw(2, "b.com")])
        assert len(entries) == 2

    def test_malformed_skipped(self) -> None:
        bad = {"id": 99, "not_before": "INVALID", "not_after": "INVALID",
               "entry_timestamp": "INVALID", "common_name": "", "name_value": ""}
        entries = parse_crtsh_response([bad])
        assert len(entries) == 0


# ---------------------------------------------------------------------------
# CTMonitorResult
# ---------------------------------------------------------------------------

class TestCTMonitorResult:
    def test_total(self) -> None:
        r = CTMonitorResult(domain="x.com", entries=[_entry(1), _entry(2)])
        assert r.total == 2

    def test_wildcard_count(self) -> None:
        r = CTMonitorResult(domain="x.com", entries=[
            _entry(name_value="*.x.com"),
            _entry(name_value="x.com"),
        ])
        assert r.wildcard_count == 1

    def test_expired_count(self) -> None:
        r = CTMonitorResult(domain="x.com", entries=[
            _entry(not_after=_PAST),
            _entry(not_after=_FUTURE),
        ])
        assert r.expired_count == 1


# ---------------------------------------------------------------------------
# detect_anomalies
# ---------------------------------------------------------------------------

class TestDetectAnomalies:
    def test_unexpected_issuer_flagged(self) -> None:
        r = CTMonitorResult(domain="x.com", entries=[
            _entry(issuer="Rogue CA")
        ])
        detect_anomalies(r, watched_issuers=["Let's Encrypt", "DigiCert"])
        assert any("UNEXPECTED_ISSUER" in a for a in r.anomalies)

    def test_trusted_issuer_no_flag(self) -> None:
        r = CTMonitorResult(domain="x.com", entries=[
            _entry(issuer="Let's Encrypt Authority X3")
        ])
        detect_anomalies(r, watched_issuers=["Let's Encrypt"])
        assert not any("UNEXPECTED_ISSUER" in a for a in r.anomalies)

    def test_issuance_spike(self) -> None:
        recent = _NOW - datetime.timedelta(hours=1)
        entries = [_entry(id=i, logged_at=recent) for i in range(6)]
        r = CTMonitorResult(domain="x.com", entries=entries)
        detect_anomalies(r)
        assert any("SPIKE" in a for a in r.anomalies)

    def test_deep_subdomain_flagged(self) -> None:
        e = _entry(common_name="a.b.c.d.e.f.example.com", name_value="a.b.c.d.e.f.example.com")
        r = CTMonitorResult(domain="example.com", entries=[e])
        detect_anomalies(r)
        assert any("DEEP_SUBDOMAIN" in a for a in r.anomalies)


# ---------------------------------------------------------------------------
# filter_entries
# ---------------------------------------------------------------------------

class TestFilterEntries:
    def test_filter_by_since(self) -> None:
        old = _entry(id=1, logged_at=_NOW - datetime.timedelta(days=10))
        new = _entry(id=2, logged_at=_NOW)
        result = filter_entries([old, new], since=_NOW - datetime.timedelta(days=1))
        assert len(result) == 1
        assert result[0].id == 2

    def test_filter_glob(self) -> None:
        a = _entry(id=1, common_name="mail.example.com")
        b = _entry(id=2, common_name="www.other.com")
        result = filter_entries([a, b], domain_glob="*.example.com")
        assert len(result) == 1

    def test_exclude_expired(self) -> None:
        expired = _entry(id=1, not_after=_PAST)
        valid = _entry(id=2, not_after=_FUTURE)
        result = filter_entries([expired, valid], include_expired=False)
        assert len(result) == 1
        assert result[0].id == 2
