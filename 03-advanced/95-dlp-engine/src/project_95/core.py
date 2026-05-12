"""DLP Engine — detect sensitive data (PII, PCI, credentials) in text files."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# ── DLP Rule model ────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class DLPRule:
    """A single DLP detection rule."""

    rule_id: str
    name: str
    category: str
    severity: str
    pattern: re.Pattern[str]
    description: str
    redact_with: str = "[REDACTED]"

    def matches(self, text: str) -> list[re.Match[str]]:
        """Return all matches in *text*."""
        return list(self.pattern.finditer(text))


# ── Built-in rules ────────────────────────────────────────────────────────────

def _rule(rule_id: str, name: str, category: str, severity: str,
          pattern: str, description: str, flags: int = re.IGNORECASE) -> DLPRule:
    return DLPRule(
        rule_id=rule_id, name=name, category=category, severity=severity,
        pattern=re.compile(pattern, flags),
        description=description,
    )


DEFAULT_RULES: tuple[DLPRule, ...] = (
    # PII
    _rule("DLP-001", "SSN", "PII", "CRITICAL",
          r'\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b',
          "US Social Security Number"),
    _rule("DLP-002", "Credit Card", "PCI", "CRITICAL",
          r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|'
          r'6(?:011|5[0-9]{2})[0-9]{12}|3(?:0[0-5]|[68][0-9])[0-9]{11}|'
          r'(?:2131|1800|35\d{3})\d{11})\b',
          "Credit card number (Visa, MC, Amex, Discover, JCB)"),
    _rule("DLP-003", "Email Address", "PII", "MEDIUM",
          r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b',
          "Email address"),
    _rule("DLP-004", "Phone Number (US)", "PII", "LOW",
          r'\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b',
          "US phone number"),
    _rule("DLP-005", "IPv4 Address", "Network", "LOW",
          r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
          "IPv4 address (may indicate network configuration)"),
    _rule("DLP-006", "AWS Access Key", "Credential", "CRITICAL",
          r'\b(?:AKIA|ASIA|AROA|AIDA|AGPA|AIPA|ANPA|ANVA|APKA)[0-9A-Z]{16}\b',
          "AWS Access Key ID"),
    _rule("DLP-007", "Private Key Header", "Credential", "CRITICAL",
          r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----',
          "PEM private key"),
    _rule("DLP-008", "Password in Config", "Credential", "HIGH",
          r'(?:password|passwd|pwd)\s*[=:]\s*["\']?(?!<)[^\s"\'<>{}\[\]]{6,}',
          "Password in configuration file", flags=re.IGNORECASE),
    _rule("DLP-009", "Database Connection String", "Credential", "HIGH",
          r'(?:mysql|postgresql|postgres|mongodb|redis|jdbc)://[^\s"\'<>]+:[^\s"\'<>@]+@',
          "Database connection string with credentials"),
    _rule("DLP-010", "GitHub Token", "Credential", "CRITICAL",
          r'\bghp_[0-9A-Za-z]{36}\b|\bgho_[0-9A-Za-z]{36}\b|\bghs_[0-9A-Za-z]{36}\b',
          "GitHub personal access token"),
    _rule("DLP-011", "IBAN", "PCI", "HIGH",
          r'\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?){0,16}\b',
          "International Bank Account Number"),
    _rule("DLP-012", "Passport Number (US)", "PII", "HIGH",
          r'\b[A-Z]{1,2}\d{6,9}\b',
          "Passport number (approximate pattern)"),
    _rule("DLP-013", "JWT Token", "Credential", "MEDIUM",
          r'\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b',
          "JSON Web Token"),
    _rule("DLP-014", "API Key Generic", "Credential", "HIGH",
          r'(?:api[_\-]?key|apikey|api_secret)\s*[=:]\s*["\']?[A-Za-z0-9\-_]{16,}',
          "Generic API key assignment", flags=re.IGNORECASE),
    _rule("DLP-015", "Date of Birth", "PII", "MEDIUM",
          r'\b(?:dob|date.of.birth|birth.?date)\s*[=:]\s*\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}\b',
          "Date of birth field", flags=re.IGNORECASE),
)


# ── Finding model ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class DLPFinding:
    """A DLP match in a file."""

    rule_id: str
    rule_name: str
    category: str
    severity: str
    file_path: str
    line_number: int
    column: int
    matched_text: str
    context: str
    description: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "category": self.category,
            "severity": self.severity,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "column": self.column,
            "matched_text": self.matched_text,
            "context": self.context,
            "description": self.description,
        }


# ── Redaction ─────────────────────────────────────────────────────────────────

def redact_text(text: str, rules: tuple[DLPRule, ...] = DEFAULT_RULES) -> str:
    """Return *text* with all sensitive data replaced by redaction markers."""
    result = text
    for rule in rules:
        result = rule.pattern.sub(rule.redact_with, result)
    return result


# ── Scanner ───────────────────────────────────────────────────────────────────

_CONTEXT_RADIUS = 40

SKIP_EXTENSIONS: frozenset[str] = frozenset({
    ".pyc", ".pyo", ".so", ".dll", ".exe", ".bin",
    ".jpg", ".jpeg", ".png", ".gif", ".ico", ".svg",
    ".pdf", ".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz",
    ".mp3", ".mp4", ".avi", ".mov",
})


def scan_text(
    text: str,
    file_path: str = "<text>",
    rules: tuple[DLPRule, ...] = DEFAULT_RULES,
) -> list[DLPFinding]:
    """Scan *text* for sensitive data matches and return findings."""
    findings: list[DLPFinding] = []
    lines = text.splitlines(keepends=True)
    line_offsets: list[int] = []
    offset = 0
    for line in lines:
        line_offsets.append(offset)
        offset += len(line)

    def _line_col(pos: int) -> tuple[int, int]:
        lo, hi = 0, len(line_offsets) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if line_offsets[mid] <= pos:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1, pos - line_offsets[lo] + 1

    for rule in rules:
        for m in rule.matches(text):
            lineno, col = _line_col(m.start())
            start = max(0, m.start() - _CONTEXT_RADIUS)
            end = min(len(text), m.end() + _CONTEXT_RADIUS)
            context = text[start:end].replace("\n", " ").strip()
            findings.append(DLPFinding(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                category=rule.category,
                severity=rule.severity,
                file_path=file_path,
                line_number=lineno,
                column=col,
                matched_text=m.group(0),
                context=context,
                description=rule.description,
            ))
    return findings


def scan_file(
    path: Path,
    rules: tuple[DLPRule, ...] = DEFAULT_RULES,
) -> list[DLPFinding]:
    """Scan a single file for sensitive data."""
    if path.suffix.lower() in SKIP_EXTENSIONS:
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return scan_text(text, file_path=str(path), rules=rules)


@dataclass
class DLPReport:
    """Full DLP scan report."""

    findings: list[DLPFinding]
    files_scanned: int
    source: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        by_cat: dict[str, int] = {}
        by_sev: dict[str, int] = {}
        for f in self.findings:
            by_cat[f.category] = by_cat.get(f.category, 0) + 1
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        return {
            "source": self.source,
            "files_scanned": self.files_scanned,
            "total_findings": len(self.findings),
            "by_category": by_cat,
            "by_severity": by_sev,
            "findings": [f.to_dict() for f in self.findings],
        }


def scan_directory(
    path: Path,
    rules: tuple[DLPRule, ...] = DEFAULT_RULES,
) -> DLPReport:
    """Recursively scan all text files in a directory."""
    all_findings: list[DLPFinding] = []
    scanned = 0
    for file_path in path.rglob("*"):
        if file_path.is_file() and file_path.suffix.lower() not in SKIP_EXTENSIONS:
            findings = scan_file(file_path, rules)
            all_findings.extend(findings)
            scanned += 1
    return DLPReport(findings=all_findings, files_scanned=scanned, source=str(path))
