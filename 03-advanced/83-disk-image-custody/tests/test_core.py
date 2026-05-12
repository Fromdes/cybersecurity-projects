"""Tests for Disk Image Hash & Chain-of-Custody core."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from project_83.core import (
    CustodyRecord,
    HashResult,
    create_custody_record,
    hash_image,
    verify_image,
)


class TestHashImage:
    def test_known_content(self, tmp_path: Path) -> None:
        content = b"forensic test data 12345"
        f = tmp_path / "image.dd"
        f.write_bytes(content)
        result = hash_image(f)
        assert result.md5 == hashlib.md5(content).hexdigest()  # noqa: S324
        assert result.sha1 == hashlib.sha1(content).hexdigest()  # noqa: S324
        assert result.sha256 == hashlib.sha256(content).hexdigest()
        assert result.sha512 == hashlib.sha512(content).hexdigest()

    def test_file_size(self, tmp_path: Path) -> None:
        content = b"x" * 4096
        f = tmp_path / "image.dd"
        f.write_bytes(content)
        result = hash_image(f)
        assert result.file_size == 4096

    def test_to_dict(self, tmp_path: Path) -> None:
        f = tmp_path / "image.dd"
        f.write_bytes(b"data")
        result = hash_image(f)
        d = result.to_dict()
        assert "sha256" in d
        assert "computed_at" in d

    def test_from_dict(self, tmp_path: Path) -> None:
        f = tmp_path / "image.dd"
        f.write_bytes(b"data")
        result = hash_image(f)
        d = result.to_dict()
        restored = HashResult.from_dict(d)
        assert restored == result

    def test_progress_callback(self, tmp_path: Path) -> None:
        f = tmp_path / "image.dd"
        f.write_bytes(b"a" * (2 * 1024 * 1024))
        calls: list[tuple[int, int]] = []
        hash_image(f, progress_callback=lambda r, t: calls.append((r, t)))
        assert len(calls) >= 2


class TestVerifyImage:
    def test_verify_correct(self, tmp_path: Path) -> None:
        content = b"test"
        f = tmp_path / "image.dd"
        f.write_bytes(content)
        expected = hashlib.sha256(content).hexdigest()
        matches, actual = verify_image(f, expected)
        assert matches is True
        assert actual == expected

    def test_verify_wrong_hash(self, tmp_path: Path) -> None:
        f = tmp_path / "image.dd"
        f.write_bytes(b"test")
        matches, actual = verify_image(f, "0" * 64)
        assert matches is False
        assert len(actual) == 64

    def test_verify_case_insensitive(self, tmp_path: Path) -> None:
        content = b"test"
        f = tmp_path / "image.dd"
        f.write_bytes(content)
        expected = hashlib.sha256(content).hexdigest().upper()
        matches, _ = verify_image(f, expected)
        assert matches is True


class TestCustodyRecord:
    def test_create_and_save(self, tmp_path: Path) -> None:
        f = tmp_path / "image.dd"
        f.write_bytes(b"disk image data")
        record = create_custody_record(f, notes="Evidence item #1")
        assert len(record.chain) == 1
        assert record.chain[0].action == "ACQUIRED"
        out = tmp_path / "custody.json"
        record.save(out)
        assert out.exists()
        data = json.loads(out.read_text())
        assert "hash_result" in data
        assert "chain" in data

    def test_load_round_trip(self, tmp_path: Path) -> None:
        f = tmp_path / "image.dd"
        f.write_bytes(b"test image")
        record = create_custody_record(f)
        out = tmp_path / "custody.json"
        record.save(out)
        loaded = CustodyRecord.load(out)
        assert loaded.hash_result.sha256 == record.hash_result.sha256
        assert len(loaded.chain) == 1

    def test_add_entry(self, tmp_path: Path) -> None:
        f = tmp_path / "image.dd"
        f.write_bytes(b"data")
        record = create_custody_record(f)
        entry = record.add_entry("TRANSFERRED", notes="Sent to lab")
        assert entry.action == "TRANSFERRED"
        assert len(record.chain) == 2

    def test_custody_chain_preserved(self, tmp_path: Path) -> None:
        f = tmp_path / "image.dd"
        f.write_bytes(b"evidence")
        record = create_custody_record(f)
        record.add_entry("TRANSFERRED", notes="To analyst")
        record.add_entry("ANALYZED", notes="Analysis complete")
        out = tmp_path / "custody.json"
        record.save(out)
        loaded = CustodyRecord.load(out)
        assert len(loaded.chain) == 3
        actions = [e.action for e in loaded.chain]
        assert actions == ["ACQUIRED", "TRANSFERRED", "ANALYZED"]
