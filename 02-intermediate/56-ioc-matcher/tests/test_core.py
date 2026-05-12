"""Tests for project 56 IOC matcher."""

from __future__ import annotations

import json
from pathlib import Path

from project_56.core import (
    IOC,
    IOCMatcher,
    IOCStore,
    IOCType,
    extract_iocs_from_text,
)


class TestExtractIOCsFromText:
    def test_ipv4(self) -> None:
        result = extract_iocs_from_text("Connection from 192.168.1.1 blocked")
        assert "192.168.1.1" in result[IOCType.IPV4]

    def test_domain(self) -> None:
        result = extract_iocs_from_text("Contacted evil.com and bad.example.org")
        domains = result[IOCType.DOMAIN]
        assert any("evil.com" in d for d in domains)

    def test_sha256(self) -> None:
        h = "a" * 64
        result = extract_iocs_from_text(f"Hash: {h}")
        assert h in result[IOCType.SHA256]

    def test_md5(self) -> None:
        h = "b" * 32
        result = extract_iocs_from_text(f"MD5: {h}")
        assert h in result[IOCType.MD5]

    def test_cve(self) -> None:
        result = extract_iocs_from_text("Exploiting CVE-2021-44228")
        assert "CVE-2021-44228" in result[IOCType.CVE]

    def test_url(self) -> None:
        result = extract_iocs_from_text("Download from http://evil.com/payload.exe")
        assert any("evil.com" in u for u in result[IOCType.URL])

    def test_email(self) -> None:
        result = extract_iocs_from_text("Sent from attacker@evil.com")
        assert "attacker@evil.com" in result[IOCType.EMAIL]

    def test_no_false_positive_sha256_as_md5(self) -> None:
        h = "a" * 64
        result = extract_iocs_from_text(h)
        assert h not in result[IOCType.MD5]
        assert h in result[IOCType.SHA256]


class TestIOCStore:
    def test_add_and_lookup(self) -> None:
        store = IOCStore()
        ioc = IOC(value="10.0.0.1", ioc_type=IOCType.IPV4, confidence=90)
        store.add(ioc)
        found = store.lookup("10.0.0.1", IOCType.IPV4)
        assert found is not None
        assert found.confidence == 90

    def test_lookup_case_insensitive(self) -> None:
        store = IOCStore()
        ioc = IOC(value="Evil.COM", ioc_type=IOCType.DOMAIN)
        store.add(ioc)
        assert store.lookup("evil.com", IOCType.DOMAIN) is not None

    def test_count(self) -> None:
        store = IOCStore()
        store.add(IOC("1.2.3.4", IOCType.IPV4))
        store.add(IOC("evil.com", IOCType.DOMAIN))
        assert store.count() == 2

    def test_from_json(self, tmp_path: Path) -> None:
        data = [{"value": "1.2.3.4", "type": "ipv4", "confidence": 80}]
        jf = tmp_path / "iocs.json"
        jf.write_text(json.dumps(data))
        store = IOCStore.from_json(jf)
        assert store.lookup("1.2.3.4", IOCType.IPV4) is not None

    def test_from_csv(self, tmp_path: Path) -> None:
        csv_content = "value,type,confidence,tags,description\n1.2.3.4,ipv4,90,c2,test\n"
        cf = tmp_path / "iocs.csv"
        cf.write_text(csv_content)
        store = IOCStore.from_csv(cf)
        assert store.lookup("1.2.3.4", IOCType.IPV4) is not None


class TestIOCMatcher:
    def _store_with(self, *iocs: IOC) -> IOCStore:
        store = IOCStore()
        for ioc in iocs:
            store.add(ioc)
        return store

    def test_match_text_hit(self) -> None:
        store = self._store_with(IOC("10.0.0.1", IOCType.IPV4, confidence=95))
        matcher = IOCMatcher(store=store)
        results = matcher.match_text("Blocked connection from 10.0.0.1 at port 443")
        assert len(results) == 1
        assert results[0].ioc.value == "10.0.0.1"

    def test_match_text_miss(self) -> None:
        store = self._store_with(IOC("10.0.0.1", IOCType.IPV4))
        matcher = IOCMatcher(store=store)
        results = matcher.match_text("clean log line")
        assert results == []

    def test_match_log_file(self, tmp_path: Path) -> None:
        log = tmp_path / "access.log"
        log.write_text("GET / from 10.0.0.2\n10.0.0.99 connected\n")
        store = self._store_with(IOC("10.0.0.99", IOCType.IPV4))
        matcher = IOCMatcher(store=store)
        results = matcher.match_log_file(log)
        assert len(results) == 1
        assert "access.log:2" in results[0].matched_in

    def test_context_captured(self) -> None:
        store = self._store_with(IOC("evil.com", IOCType.DOMAIN))
        matcher = IOCMatcher(store=store)
        results = matcher.match_text("Request to evil.com was blocked by firewall")
        assert "evil.com" in results[0].context
