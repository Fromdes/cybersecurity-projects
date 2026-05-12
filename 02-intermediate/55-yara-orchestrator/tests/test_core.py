"""Tests for project 55 YARA orchestrator (yara-python mocked)."""

from __future__ import annotations

import sys
import types
from pathlib import Path
from unittest.mock import MagicMock, patch
import tempfile

import pytest


# ---------------------------------------------------------------------------
# Stub yara module so tests run without yara-python installed
# ---------------------------------------------------------------------------

def _make_yara_stub() -> types.ModuleType:
    """Return a minimal yara stub compatible with our usage."""
    yara_mod = types.ModuleType("yara")

    class FakeMatch:
        def __init__(self, rule: str = "TestRule") -> None:
            self.rule = rule
            self.namespace = "default"
            self.tags: list[str] = ["malware"]
            self.meta: dict = {"description": "Test"}
            self.strings: list = []

    class FakeRules:
        def match(self, filepath: str | None = None, data: bytes | None = None,
                  timeout: int = 60) -> list[FakeMatch]:
            if filepath and "evil" in filepath:
                return [FakeMatch("EvilDetected")]
            if data and b"evil_string" in data:
                return [FakeMatch("BytesRule")]
            return []

    def compile(source: str | None = None, filepaths: dict | None = None) -> FakeRules:  # noqa: A001
        return FakeRules()

    yara_mod.compile = compile  # type: ignore[attr-defined]
    return yara_mod


# Inject stub before importing our module
sys.modules.setdefault("yara", _make_yara_stub())

# Now we can import
from project_55.core import (  # noqa: E402
    RuleLoader,
    RuleMatch,
    ScanReport,
    YARAScanner,
)


class TestRuleLoader:
    def test_list_rule_files(self, tmp_path: Path) -> None:
        (tmp_path / "test.yar").write_text("rule X {condition: true}")
        (tmp_path / "other.yara").write_text("rule Y {condition: true}")
        (tmp_path / "ignore.txt").write_text("ignored")
        loader = RuleLoader(rules_dir=tmp_path)
        files = loader.list_rule_files()
        assert len(files) == 2
        assert all(f.suffix in {".yar", ".yara"} for f in files)

    def test_compile_no_files_raises(self, tmp_path: Path) -> None:
        loader = RuleLoader(rules_dir=tmp_path)
        with pytest.raises(FileNotFoundError):
            loader.compile()

    def test_compile_succeeds(self, tmp_path: Path) -> None:
        (tmp_path / "test.yar").write_text("rule X {condition: true}")
        loader = RuleLoader(rules_dir=tmp_path)
        compiled = loader.compile()
        assert compiled is not None


class TestYARAScanner:
    def _scanner(self) -> YARAScanner:
        import yara
        return YARAScanner(compiled_rules=yara.compile(source="rule X {condition: true}"))

    def test_scan_file_no_match(self, tmp_path: Path) -> None:
        target = tmp_path / "clean.txt"
        target.write_bytes(b"harmless content")
        scanner = self._scanner()
        matches = scanner.scan_file(target)
        assert matches == []

    def test_scan_file_match(self, tmp_path: Path) -> None:
        target = tmp_path / "evil_file.txt"
        target.write_bytes(b"evil content")
        scanner = self._scanner()
        matches = scanner.scan_file(target)
        assert len(matches) == 1
        assert matches[0].rule_name == "EvilDetected"

    def test_scan_directory(self, tmp_path: Path) -> None:
        (tmp_path / "clean.txt").write_bytes(b"safe")
        (tmp_path / "evil_payload.bin").write_bytes(b"evil content")
        scanner = self._scanner()
        report = scanner.scan_directory(tmp_path, recursive=False)
        assert report.scanned_files == 2
        assert report.matched_files == 1

    def test_scan_directory_skips_large_files(self, tmp_path: Path) -> None:
        big = tmp_path / "evil_big.bin"
        big.write_bytes(b"evil" * 1000)
        scanner = self._scanner()
        # max_file_size_mb=0 should skip everything
        report = scanner.scan_directory(tmp_path, max_file_size_mb=0)
        assert report.scanned_files == 0


class TestScanReport:
    def test_summary(self) -> None:
        report = ScanReport(scanned_files=10, matched_files=2)
        report.add_match(RuleMatch(
            rule_name="X", namespace="ns", tags=(), meta={}, strings=[], file_path="/f"
        ))
        summary = report.summary()
        assert "10" in summary
        assert "2" in summary
