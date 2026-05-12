"""Tests for Office Macro Risk Analyzer core."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from project_80.core import (
    MacroAnalyzer,
    RiskIndicator,
    _scan_vba_text,
    _score_from_indicators,
)


class TestScanVbaText:
    def test_detects_shell(self) -> None:
        indicators = _scan_vba_text("x = Shell(cmd, 1)")
        assert any(ind.category == "shell_execution" for ind in indicators)

    def test_detects_powershell(self) -> None:
        indicators = _scan_vba_text('Shell "powershell -enc ..."')
        assert any(ind.category == "powershell" for ind in indicators)

    def test_detects_download(self) -> None:
        indicators = _scan_vba_text("URLDownloadToFile url, path")
        assert any(ind.category == "download" for ind in indicators)

    def test_detects_auto_exec(self) -> None:
        indicators = _scan_vba_text("Sub AutoOpen()\nEnd Sub")
        assert any(ind.category == "auto_exec" for ind in indicators)

    def test_detects_chr_obfuscation(self) -> None:
        indicators = _scan_vba_text("x = Chr(80) & Chr(79) & Chr(87)")
        assert any(ind.category == "obfuscation_chr" for ind in indicators)

    def test_clean_vba_no_indicators(self) -> None:
        indicators = _scan_vba_text("Sub HelloWorld()\n  MsgBox \"Hello\"\nEnd Sub")
        assert indicators == []

    def test_no_duplicate_categories(self) -> None:
        code = "Shell cmd\nShell cmd2\nShell cmd3"
        indicators = _scan_vba_text(code)
        categories = [ind.category for ind in indicators]
        assert len(categories) == len(set(categories))


class TestScoreFromIndicators:
    def test_empty_zero(self) -> None:
        assert _score_from_indicators([]) == 0

    def test_critical_weight(self) -> None:
        ind = RiskIndicator("test", "desc", "CRITICAL")
        score = _score_from_indicators([ind])
        assert score == 40

    def test_capped_at_100(self) -> None:
        indicators = [RiskIndicator(f"cat{i}", "desc", "CRITICAL") for i in range(10)]
        assert _score_from_indicators(indicators) == 100

    def test_mixed_severities(self) -> None:
        indicators = [
            RiskIndicator("a", "d", "HIGH"),
            RiskIndicator("b", "d", "MEDIUM"),
            RiskIndicator("c", "d", "LOW"),
        ]
        score = _score_from_indicators(indicators)
        assert 0 < score <= 100


class TestMacroAnalyzer:
    def test_analyze_text_file(self, tmp_path: Path) -> None:
        f = tmp_path / "doc.txt"
        f.write_text("This is just a plain text file, no macros.")
        analyzer = MacroAnalyzer()
        result = analyzer.analyze(f)
        assert result.sha256 != ""
        assert result.risk_score >= 0

    def test_analyze_file_with_suspicious_content(self, tmp_path: Path) -> None:
        f = tmp_path / "macro.doc"
        vba_content = (
            b"\xd0\xcf\x11\xe0" + b"\x00" * 100
            + b"Sub AutoOpen()\nShell \"powershell -enc abc\"\nURLDownloadToFile url\nEnd Sub"
        )
        f.write_bytes(vba_content)
        analyzer = MacroAnalyzer()
        result = analyzer.analyze(f)
        assert result.risk_score > 0

    def test_analyze_to_dict(self, tmp_path: Path) -> None:
        f = tmp_path / "file.bin"
        f.write_bytes(b"test content")
        analyzer = MacroAnalyzer()
        result = analyzer.analyze(f)
        d = result.to_dict()
        assert "sha256" in d
        assert "risk_score" in d
        assert "indicators" in d

    def test_regex_fallback_invoked_without_oletools(self, tmp_path: Path) -> None:
        f = tmp_path / "macro.xlsm"
        f.write_bytes(b"PK\x03\x04" + b"Sub AutoOpen\nShell cmd\nEnd Sub")
        analyzer = MacroAnalyzer()

        # Force ImportError for oletools
        with patch("builtins.__import__", side_effect=lambda name, *a, **k: (_ for _ in ()).throw(
            ImportError("oletools not found")) if name == "oletools.olevba" else __import__(name, *a, **k)
        ):
            result = analyzer._analyze_regex_fallback(f, f.read_bytes(), "abc", "OOXML")
        assert result.oletools_available is False
