"""Tests for Memory Dump IOC Extractor core."""

from __future__ import annotations

from pathlib import Path

import pytest

from project_82.core import IOCExtractor, _is_private_ip, _looks_like_hash_text


class TestPrivateIPFilter:
    def test_loopback(self) -> None:
        assert _is_private_ip(b"127.0.0.1")

    def test_rfc1918_10(self) -> None:
        assert _is_private_ip(b"10.0.0.1")

    def test_rfc1918_192(self) -> None:
        assert _is_private_ip(b"192.168.1.1")

    def test_rfc1918_172(self) -> None:
        assert _is_private_ip(b"172.16.0.1")
        assert _is_private_ip(b"172.31.255.255")
        assert not _is_private_ip(b"172.32.0.1")

    def test_public_ip(self) -> None:
        assert not _is_private_ip(b"8.8.8.8")
        assert not _is_private_ip(b"1.1.1.1")


class TestHashTextFilter:
    def test_valid_hash(self) -> None:
        h = b"a" * 8 + b"1" * 8 + b"f" * 8 + b"e" * 8  # 32 chars mixed
        assert _looks_like_hash_text(h)

    def test_all_same_char(self) -> None:
        assert not _looks_like_hash_text(b"a" * 32)

    def test_all_digits(self) -> None:
        assert not _looks_like_hash_text(b"1234567890123456789012345678901234567890")


class TestIOCExtractor:
    def setup_method(self) -> None:
        self.extractor = IOCExtractor()

    def test_extracts_public_ip(self) -> None:
        data = b"Connection from 8.8.8.8 detected"
        result = self.extractor.extract_from_bytes(data)
        assert "8.8.8.8" in result["ipv4"]

    def test_ignores_private_ip(self) -> None:
        data = b"Local connection 192.168.1.1 internal"
        result = self.extractor.extract_from_bytes(data)
        assert "192.168.1.1" not in result["ipv4"]

    def test_extracts_url(self) -> None:
        data = b"Download from http://malicious.com/payload.exe now"
        result = self.extractor.extract_from_bytes(data)
        assert any("malicious.com" in url for url in result["url"])

    def test_extracts_https_url(self) -> None:
        data = b"Beacon to https://c2server.xyz/update/check"
        result = self.extractor.extract_from_bytes(data)
        assert any("c2server.xyz" in url for url in result["url"])

    def test_extracts_email(self) -> None:
        data = b"Contact attacker@evil.com for ransom"
        result = self.extractor.extract_from_bytes(data)
        assert "attacker@evil.com" in result["email"]

    def test_extracts_windows_path(self) -> None:
        data = b"Dropped to C:\\Windows\\Temp\\malware.exe"
        result = self.extractor.extract_from_bytes(data)
        assert any("Windows" in p for p in result["windows_path"])

    def test_extracts_registry_key(self) -> None:
        data = b"Persistence: HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        result = self.extractor.extract_from_bytes(data)
        assert len(result["registry_key"]) > 0

    def test_empty_data(self) -> None:
        result = self.extractor.extract_from_bytes(b"")
        assert all(len(v) == 0 for v in result.values())

    def test_extract_from_file(self, tmp_path: Path) -> None:
        f = tmp_path / "dump.bin"
        f.write_bytes(b"C2 server at 8.8.4.4 - beacon to http://evil.com/c2/update " * 10)
        result = self.extractor.extract_from_file(f)
        assert result.file_size == f.stat().st_size
        assert result.sha256 != ""
        assert result.total_count > 0

    def test_file_too_large_raises(self, tmp_path: Path) -> None:
        f = tmp_path / "huge.bin"
        f.write_bytes(b"x" * 100)
        with pytest.raises(ValueError, match="exceeds"):
            self.extractor.extract_from_file(f, max_size_gb=0.000000001)

    def test_to_dict(self, tmp_path: Path) -> None:
        f = tmp_path / "sample.bin"
        f.write_bytes(b"IP 8.8.8.8 and http://example.com/payload ")
        result = self.extractor.extract_from_file(f)
        d = result.to_dict()
        assert "sha256" in d
        assert "iocs" in d
        assert "total_ioc_count" in d
