"""Unit tests for project_03.core."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from project_03.core import (
    IntegrityReport,
    check_integrity,
    create_baseline,
    load_baseline,
    save_baseline,
)


@pytest.fixture()
def sample_dir(tmp_path: Path) -> Path:
    (tmp_path / "a.txt").write_bytes(b"hello")
    (tmp_path / "b.txt").write_bytes(b"world")
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "c.txt").write_bytes(b"deep")
    return tmp_path


class TestCreateBaseline:
    def test_returns_all_files(self, sample_dir: Path) -> None:
        baseline = create_baseline(sample_dir)
        assert "a.txt" in baseline
        assert "b.txt" in baseline
        assert "sub/c.txt" in baseline

    def test_hashes_are_hex_strings(self, sample_dir: Path) -> None:
        baseline = create_baseline(sample_dir)
        for digest in baseline.values():
            assert all(c in "0123456789abcdef" for c in digest)

    def test_exclude_works(self, sample_dir: Path) -> None:
        baseline = create_baseline(sample_dir, exclude={"a.txt"})
        assert "a.txt" not in baseline
        assert "b.txt" in baseline

    def test_non_directory_raises(self, tmp_path: Path) -> None:
        f = tmp_path / "file.txt"
        f.write_bytes(b"x")
        with pytest.raises(NotADirectoryError):
            create_baseline(f)


class TestCheckIntegrity:
    def test_clean_baseline(self, sample_dir: Path) -> None:
        baseline = create_baseline(sample_dir)
        report = check_integrity(sample_dir, baseline)
        assert report.is_clean

    def test_detects_new_file(self, sample_dir: Path) -> None:
        baseline = create_baseline(sample_dir)
        (sample_dir / "new.txt").write_bytes(b"new")
        report = check_integrity(sample_dir, baseline)
        assert "new.txt" in report.new_files

    def test_detects_deleted_file(self, sample_dir: Path) -> None:
        baseline = create_baseline(sample_dir)
        (sample_dir / "a.txt").unlink()
        report = check_integrity(sample_dir, baseline)
        assert "a.txt" in report.deleted_files

    def test_detects_modified_file(self, sample_dir: Path) -> None:
        baseline = create_baseline(sample_dir)
        (sample_dir / "b.txt").write_bytes(b"tampered!")
        report = check_integrity(sample_dir, baseline)
        assert "b.txt" in report.modified_files

    def test_summary_clean(self, sample_dir: Path) -> None:
        baseline = create_baseline(sample_dir)
        report = check_integrity(sample_dir, baseline)
        assert "CLEAN" in report.summary()

    def test_summary_changed(self, sample_dir: Path) -> None:
        baseline = create_baseline(sample_dir)
        (sample_dir / "a.txt").write_bytes(b"changed")
        report = check_integrity(sample_dir, baseline)
        assert "CHANGED" in report.summary()


class TestSaveLoadBaseline:
    def test_roundtrip(self, tmp_path: Path, sample_dir: Path) -> None:
        baseline = create_baseline(sample_dir)
        path = tmp_path / "baseline.json"
        save_baseline(baseline, path)
        loaded = load_baseline(path)
        assert baseline == loaded

    def test_load_missing_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            load_baseline(tmp_path / "no.json")

    def test_load_invalid_json_raises(self, tmp_path: Path) -> None:
        f = tmp_path / "bad.json"
        f.write_text("not json", encoding="utf-8")
        with pytest.raises(ValueError):
            load_baseline(f)

    def test_load_wrong_type_raises(self, tmp_path: Path) -> None:
        f = tmp_path / "wrong.json"
        f.write_text(json.dumps([1, 2, 3]), encoding="utf-8")
        with pytest.raises(ValueError):
            load_baseline(f)


class TestIntegrityReport:
    def test_is_clean_when_no_changes(self) -> None:
        report = IntegrityReport(
            baseline_path=Path("."),
            checked_at="2024-01-01T00:00:00+00:00",
        )
        assert report.is_clean

    def test_is_not_clean_with_changes(self) -> None:
        report = IntegrityReport(
            baseline_path=Path("."),
            checked_at="2024-01-01T00:00:00+00:00",
            modified_files=["secret.conf"],
        )
        assert not report.is_clean
