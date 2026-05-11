"""Unit tests for project_02.core."""

from __future__ import annotations

from pathlib import Path

import pytest

from project_02.core import (
    SUPPORTED_ALGORITHMS,
    hash_file,
    hash_file_all,
    hash_text,
    verify_hash,
)


class TestHashText:
    """Tests for hash_text."""

    def test_sha256_known_value(self) -> None:
        # SHA-256 of empty string
        result = hash_text("", "sha256")
        assert result == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_sha256_hello(self) -> None:
        result = hash_text("hello", "sha256")
        assert len(result) == 64

    def test_all_algorithms_produce_output(self) -> None:
        for alg in SUPPORTED_ALGORITHMS:
            digest = hash_text("test", alg)
            assert isinstance(digest, str)
            assert len(digest) > 0

    def test_unsupported_algorithm_raises(self) -> None:
        with pytest.raises(ValueError, match="Unsupported algorithm"):
            hash_text("hello", "rot13")

    def test_encoding_parameter(self) -> None:
        result = hash_text("hello", "sha256", encoding="utf-8")
        assert isinstance(result, str)


class TestHashFile:
    """Tests for hash_file."""

    def test_hash_file_sha256(self, tmp_path: Path) -> None:
        f = tmp_path / "test.txt"
        f.write_bytes(b"hello")
        result = hash_file(f, "sha256")
        expected = hash_text("hello", "sha256")
        assert result == expected

    def test_hash_file_missing_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            hash_file(tmp_path / "nonexistent.txt", "sha256")

    def test_hash_file_unsupported_algorithm(self, tmp_path: Path) -> None:
        f = tmp_path / "test.txt"
        f.write_bytes(b"data")
        with pytest.raises(ValueError):
            hash_file(f, "crc32")

    def test_large_file_chunked(self, tmp_path: Path) -> None:
        f = tmp_path / "large.bin"
        data = b"x" * (2 << 20)  # 2 MiB — forces multiple chunks
        f.write_bytes(data)
        result = hash_file(f, "sha256")
        assert len(result) == 64


class TestHashFileAll:
    """Tests for hash_file_all."""

    def test_returns_all_algorithms(self, tmp_path: Path) -> None:
        f = tmp_path / "test.txt"
        f.write_bytes(b"data")
        results = hash_file_all(f)
        assert set(results.keys()) == SUPPORTED_ALGORITHMS

    def test_sha256_matches_hash_file(self, tmp_path: Path) -> None:
        f = tmp_path / "test.txt"
        f.write_bytes(b"hello world")
        all_hashes = hash_file_all(f)
        single = hash_file(f, "sha256")
        assert all_hashes["sha256"] == single


class TestVerifyHash:
    """Tests for verify_hash."""

    def test_correct_hash_returns_true(self, tmp_path: Path) -> None:
        f = tmp_path / "test.txt"
        f.write_bytes(b"verify me")
        digest = hash_file(f, "sha256")
        assert verify_hash(f, "sha256", digest) is True

    def test_wrong_hash_returns_false(self, tmp_path: Path) -> None:
        f = tmp_path / "test.txt"
        f.write_bytes(b"data")
        assert verify_hash(f, "sha256", "wrong" * 10) is False

    def test_case_insensitive_comparison(self, tmp_path: Path) -> None:
        f = tmp_path / "test.txt"
        f.write_bytes(b"case")
        digest = hash_file(f, "sha256").upper()
        assert verify_hash(f, "sha256", digest) is True
