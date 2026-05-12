"""Tests for project_32.core — Hosts File Tamper Detector."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from project_32.core import (
    _is_suspicious_redirect,
    detect_tampering,
    hash_file,
    load_baseline,
    parse_hosts,
    save_baseline,
)

SAMPLE_HOSTS = """\
# Standard loopback
127.0.0.1 localhost
::1       localhost ip6-localhost
192.168.1.10 myserver myserver.local
"""

MODIFIED_HOSTS = """\
127.0.0.1 localhost
::1       localhost ip6-localhost
192.168.1.10 myserver myserver.local
1.2.3.4 paypal.com
"""


class TestParseHosts:
    def test_skips_comments(self, tmp_path: Path) -> None:
        f = tmp_path / "hosts"
        f.write_text(SAMPLE_HOSTS)
        entries = parse_hosts(f)
        assert all(not e.raw_line.strip().startswith("#") for e in entries)

    def test_parses_basic_entry(self, tmp_path: Path) -> None:
        f = tmp_path / "hosts"
        f.write_text("127.0.0.1 localhost\n")
        entries = parse_hosts(f)
        assert len(entries) == 1
        assert entries[0].ip == "127.0.0.1"
        assert entries[0].hostname == "localhost"

    def test_parses_aliases(self, tmp_path: Path) -> None:
        f = tmp_path / "hosts"
        f.write_text("192.168.1.10 myserver myserver.local\n")
        entries = parse_hosts(f)
        assert "myserver.local" in entries[0].aliases

    def test_file_not_found(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            parse_hosts(tmp_path / "nonexistent")

    def test_empty_file(self, tmp_path: Path) -> None:
        f = tmp_path / "hosts"
        f.write_text("")
        assert parse_hosts(f) == []


class TestHashFile:
    def test_same_content_same_hash(self, tmp_path: Path) -> None:
        f = tmp_path / "hosts"
        f.write_text("127.0.0.1 localhost")
        h1 = hash_file(f)
        h2 = hash_file(f)
        assert h1 == h2

    def test_different_content_different_hash(self, tmp_path: Path) -> None:
        f = tmp_path / "hosts"
        f.write_text("127.0.0.1 localhost")
        h1 = hash_file(f)
        f.write_text("127.0.0.1 localhost\n1.2.3.4 evil.com")
        h2 = hash_file(f)
        assert h1 != h2

    def test_hash_is_hex(self, tmp_path: Path) -> None:
        f = tmp_path / "hosts"
        f.write_text("data")
        h = hash_file(f)
        assert len(h) == 64
        int(h, 16)


class TestBaselineSaveLoad:
    def test_save_and_load_roundtrip(self, tmp_path: Path) -> None:
        hosts = tmp_path / "hosts"
        hosts.write_text(SAMPLE_HOSTS)
        baseline_path = tmp_path / "baseline.json"
        saved = save_baseline(hosts, baseline_path)
        loaded = load_baseline(baseline_path)
        assert saved["hash"] == loaded["hash"]

    def test_load_invalid_raises(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.json"
        bad.write_text(json.dumps({"wrong": "keys"}))
        with pytest.raises(ValueError, match="Invalid baseline"):
            load_baseline(bad)

    def test_load_nonexistent_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            load_baseline(tmp_path / "missing.json")


class TestDetectTampering:
    def test_no_changes_not_tampered(self, tmp_path: Path) -> None:
        hosts = tmp_path / "hosts"
        hosts.write_text(SAMPLE_HOSTS)
        baseline_path = tmp_path / "baseline.json"
        baseline = save_baseline(hosts, baseline_path)
        result = detect_tampering(baseline, hosts)
        assert not result.is_tampered
        assert not result.hash_changed

    def test_added_entry_detected(self, tmp_path: Path) -> None:
        hosts = tmp_path / "hosts"
        hosts.write_text(SAMPLE_HOSTS)
        baseline_path = tmp_path / "baseline.json"
        baseline = save_baseline(hosts, baseline_path)
        hosts.write_text(MODIFIED_HOSTS)
        result = detect_tampering(baseline, hosts)
        assert result.hash_changed
        assert any("paypal.com" in a for a in result.added)

    def test_suspicious_redirect_flagged(self, tmp_path: Path) -> None:
        hosts = tmp_path / "hosts"
        hosts.write_text(SAMPLE_HOSTS)
        baseline_path = tmp_path / "baseline.json"
        baseline = save_baseline(hosts, baseline_path)
        hosts.write_text(MODIFIED_HOSTS)
        result = detect_tampering(baseline, hosts)
        assert result.suspicious

    def test_removed_entry_detected(self, tmp_path: Path) -> None:
        hosts = tmp_path / "hosts"
        hosts.write_text(SAMPLE_HOSTS)
        baseline_path = tmp_path / "baseline.json"
        baseline = save_baseline(hosts, baseline_path)
        hosts.write_text("127.0.0.1 localhost\n")
        result = detect_tampering(baseline, hosts)
        assert result.removed


class TestSuspiciousRedirect:
    def test_loopback_not_suspicious(self) -> None:
        assert not _is_suspicious_redirect("127.0.0.1", "paypal.com")

    def test_external_ip_to_known_domain_is_suspicious(self) -> None:
        assert _is_suspicious_redirect("1.2.3.4", "paypal.com")

    def test_unknown_domain_not_suspicious(self) -> None:
        assert not _is_suspicious_redirect("1.2.3.4", "mycustomdomain.example")
