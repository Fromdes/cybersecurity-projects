"""Office Macro Risk Analyzer — static VBA macro analysis via oletools."""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ── Risk indicators ────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class RiskIndicator:
    """A specific risk indicator found in a macro."""

    category: str
    description: str
    severity: str  # LOW / MEDIUM / HIGH / CRITICAL
    snippet: str = ""
    mitre_technique: str = ""


# Regex patterns for VBA analysis without oletools
_VBA_PATTERNS: list[tuple[str, re.Pattern[str], str, str, str]] = [
    ("shell_execution", re.compile(r"\bShell\b|\bWScript\.Shell\b|\bCreateObject\s*\(\s*[\"']WScript", re.IGNORECASE),
     "Shell execution API", "HIGH", "T1059.005"),
    ("powershell", re.compile(r"powershell|pwsh", re.IGNORECASE),
     "PowerShell invocation", "HIGH", "T1059.001"),
    ("cmd_execution", re.compile(r'cmd\.exe|/c\s+"', re.IGNORECASE),
     "CMD execution", "HIGH", "T1059.003"),
    ("download", re.compile(r"URLDownloadToFile|XMLHTTP|WinHttp|InternetOpen|DownloadFile", re.IGNORECASE),
     "Network download capability", "CRITICAL", "T1105"),
    ("auto_exec", re.compile(r"\bAutoOpen\b|\bDocument_Open\b|\bAuto_Open\b|\bWorkbook_Open\b|\bAutoExec\b", re.IGNORECASE),
     "Auto-execution trigger", "HIGH", "T1204.002"),
    ("registry", re.compile(r"RegRead|RegWrite|HKEY_|CreateKey|OpenKey", re.IGNORECASE),
     "Registry access", "MEDIUM", "T1112"),
    ("file_write", re.compile(r"\bOpen\b.{0,30}\bFor\s+Output\b|\bPut\s+#", re.IGNORECASE),
     "File write operation", "MEDIUM", "T1074"),
    ("obfuscation_chr", re.compile(r"Chr\s*\(\s*\d+\s*\)", re.IGNORECASE),
     "Chr() obfuscation", "MEDIUM", "T1027"),
    ("obfuscation_concat", re.compile(r'("[^"]{1,3}"\s*&\s*){3,}', re.IGNORECASE),
     "String concatenation obfuscation", "MEDIUM", "T1027"),
    ("environ", re.compile(r"Environ\s*\(|GetEnvironmentVariable", re.IGNORECASE),
     "Environment variable access", "LOW", "T1082"),
    ("wmi", re.compile(r"WMI|winmgmts|GetObject\s*\(\s*[\"']winmgmts", re.IGNORECASE),
     "WMI access", "HIGH", "T1047"),
    ("base64", re.compile(r"Base64|FromBase64String|ToBase64String", re.IGNORECASE),
     "Base64 encoding/decoding", "MEDIUM", "T1027"),
    ("disable_security", re.compile(r"AutomationSecurity|DisableAllMacros|VBAWarnings|ProtectedView", re.IGNORECASE),
     "Security feature modification", "CRITICAL", "T1562"),
    ("process_create", re.compile(r"CreateObject\s*\(\s*[\"']ADODB|WbemScripting|Process\.Create", re.IGNORECASE),
     "Process/COM object creation", "HIGH", "T1055"),
    ("scheduled_task", re.compile(r"Schedule\.Service|TaskScheduler|schtasks", re.IGNORECASE),
     "Scheduled task manipulation", "HIGH", "T1053"),
]


# ── Document formats ───────────────────────────────────────────────────────────

SUPPORTED_EXTENSIONS: frozenset[str] = frozenset({
    ".doc", ".docm", ".xls", ".xlsm", ".xlsb", ".ppt", ".pptm",
    ".docx", ".xlsx", ".pptx", ".dotm", ".xlam", ".xltm",
})

OLE2_MAGIC = b"\xd0\xcf\x11\xe0"


def _is_ole2(data: bytes) -> bool:
    return data[:4] == OLE2_MAGIC


def _is_ooxml(data: bytes) -> bool:
    return data[:2] == b"PK"


# ── Analysis result ────────────────────────────────────────────────────────────

@dataclass
class MacroAnalysisResult:
    """Analysis result for an Office document."""

    file_path: str
    file_size: int
    sha256: str
    file_format: str
    has_macros: bool
    vba_code: list[str]
    indicators: list[RiskIndicator]
    risk_score: int
    oletools_available: bool
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "file_path": self.file_path,
            "file_size": self.file_size,
            "sha256": self.sha256,
            "file_format": self.file_format,
            "has_macros": self.has_macros,
            "vba_modules": len(self.vba_code),
            "indicators": [
                {
                    "category": ind.category,
                    "description": ind.description,
                    "severity": ind.severity,
                    "snippet": ind.snippet[:100],
                    "mitre": ind.mitre_technique,
                }
                for ind in self.indicators
            ],
            "risk_score": self.risk_score,
            "error": self.error,
        }


# ── Fallback VBA regex scanner ─────────────────────────────────────────────────

def _scan_vba_text(vba_text: str) -> list[RiskIndicator]:
    """Scan VBA source text with regex patterns."""
    found: list[RiskIndicator] = []
    seen_categories: set[str] = set()
    for category, pattern, description, severity, mitre in _VBA_PATTERNS:
        m = pattern.search(vba_text)
        if m and category not in seen_categories:
            seen_categories.add(category)
            snippet = vba_text[max(0, m.start() - 20): m.end() + 20].strip().replace("\n", " ")
            found.append(RiskIndicator(
                category=category,
                description=description,
                severity=severity,
                snippet=snippet,
                mitre_technique=mitre,
            ))
    return found


def _score_from_indicators(indicators: list[RiskIndicator]) -> int:
    """Compute risk score 0–100 from indicator severities."""
    weights = {"LOW": 5, "MEDIUM": 15, "HIGH": 25, "CRITICAL": 40}
    score = sum(weights.get(ind.severity, 0) for ind in indicators)
    return min(100, score)


# ── Main analyzer ──────────────────────────────────────────────────────────────

class MacroAnalyzer:
    """Analyzes Office documents for malicious VBA macros."""

    def analyze(self, file_path: Path) -> MacroAnalysisResult:
        """Analyze an Office document for macro-based risks."""
        data = file_path.read_bytes()
        sha256 = hashlib.sha256(data).hexdigest()
        ext = file_path.suffix.lower()

        if _is_ole2(data):
            file_format = "OLE2"
        elif _is_ooxml(data):
            file_format = "OOXML"
        else:
            file_format = "UNKNOWN"

        # Try oletools first, fall back to regex scan
        try:
            return self._analyze_with_oletools(file_path, data, sha256, file_format)
        except ImportError:
            logger.info("oletools not available; using regex-based analysis")
            return self._analyze_regex_fallback(file_path, data, sha256, file_format)
        except Exception as exc:
            logger.warning("oletools analysis failed: %s", exc)
            return self._analyze_regex_fallback(file_path, data, sha256, file_format)

    def _analyze_with_oletools(
        self, file_path: Path, data: bytes, sha256: str, file_format: str
    ) -> MacroAnalysisResult:
        """Use oletools olevba for VBA extraction."""
        from oletools.olevba import VBA_Parser  # type: ignore[import-untyped]

        vba_parser = VBA_Parser(str(file_path), data=data)
        has_macros = vba_parser.detect_vba_macros()
        vba_code_list: list[str] = []
        all_indicators: list[RiskIndicator] = []

        if has_macros:
            for _, _, vba_filename, vba_code in vba_parser.extract_macros():
                vba_code_list.append(vba_code)
                indicators = _scan_vba_text(vba_code)
                all_indicators.extend(indicators)

            # Also use oletools built-in analysis
            analysis = vba_parser.analyze_macros()
            for kw_type, keyword, description in analysis:
                if kw_type in ("AutoExec", "Suspicious", "IOC"):
                    all_indicators.append(RiskIndicator(
                        category=kw_type.lower(),
                        description=f"[oletools] {description}",
                        severity="HIGH" if kw_type == "Suspicious" else "MEDIUM",
                        snippet=keyword,
                    ))

        risk_score = _score_from_indicators(all_indicators)
        return MacroAnalysisResult(
            file_path=str(file_path),
            file_size=len(data),
            sha256=sha256,
            file_format=file_format,
            has_macros=has_macros,
            vba_code=vba_code_list,
            indicators=all_indicators,
            risk_score=risk_score,
            oletools_available=True,
        )

    def _analyze_regex_fallback(
        self, file_path: Path, data: bytes, sha256: str, file_format: str
    ) -> MacroAnalysisResult:
        """Fallback: scan raw bytes with regex patterns for VBA indicators."""
        text = data.decode("latin-1", errors="replace")
        indicators = _scan_vba_text(text)
        has_macros = any(
            kw in text
            for kw in ("Sub ", "Function ", "End Sub", "End Function", "VBA", "Macro")
        )
        risk_score = _score_from_indicators(indicators)
        return MacroAnalysisResult(
            file_path=str(file_path),
            file_size=len(data),
            sha256=sha256,
            file_format=file_format,
            has_macros=has_macros,
            vba_code=[],
            indicators=indicators,
            risk_score=risk_score,
            oletools_available=False,
        )
