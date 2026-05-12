"""Secrets Scanner — detect hardcoded secrets, API keys, and credentials in source code."""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# ── Secret patterns ────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class SecretRule:
    """A rule for detecting a specific type of secret."""

    name: str
    pattern: re.Pattern[str]
    severity: str
    description: str
    mitre_technique: str = "T1552"


BUILTIN_RULES: tuple[SecretRule, ...] = (
    SecretRule("AWS_ACCESS_KEY", re.compile(r"AKIA[0-9A-Z]{16}"), "CRITICAL", "AWS access key ID"),
    SecretRule("AWS_SECRET_KEY", re.compile(r'(?i)aws.{0,20}secret.{0,20}["\']?[A-Za-z0-9/+=]{40}["\']?'), "CRITICAL", "AWS secret access key"),
    SecretRule("GITHUB_TOKEN", re.compile(r"ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}"), "CRITICAL", "GitHub personal access token"),
    SecretRule("GOOGLE_API_KEY", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "HIGH", "Google API key"),
    SecretRule("STRIPE_KEY", re.compile(r"sk_(live|test)_[A-Za-z0-9]{24,99}"), "CRITICAL", "Stripe secret key"),
    SecretRule("SLACK_TOKEN", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,48}"), "HIGH", "Slack API token"),
    SecretRule("PRIVATE_KEY_HEADER", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), "CRITICAL", "Private key material"),
    SecretRule("JWT_TOKEN", re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"), "HIGH", "JSON Web Token"),
    SecretRule("GENERIC_PASSWORD", re.compile(r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']?[^\s"\']{8,}["\']?'), "HIGH", "Hardcoded password"),
    SecretRule("GENERIC_SECRET", re.compile(r'(?i)(?:secret|api_?key|api_?secret|auth_?token|access_?token)\s*[=:]\s*["\']?[A-Za-z0-9+/=_\-]{16,}["\']?'), "HIGH", "Generic hardcoded secret"),
    SecretRule("DATABASE_URL", re.compile(r'(?i)(?:postgres|mysql|mongodb|redis|mssql|sqlite)://[A-Za-z0-9._\-]+:[^@\s"\']{4,}@'), "CRITICAL", "Database connection string with credentials"),
    SecretRule("PRIVATE_IP_HARDCODED", re.compile(r'(?i)(?:host|server|endpoint)\s*[=:]\s*["\']?(?:10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168\.)'), "LOW", "Hardcoded internal IP address"),
    SecretRule("SSH_DSA_KEY", re.compile(r"-----BEGIN DSA PRIVATE KEY-----"), "CRITICAL", "DSA private key"),
    SecretRule("HEROKU_KEY", re.compile(r"heroku.*[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE), "HIGH", "Heroku API key"),
    SecretRule("SENDGRID_KEY", re.compile(r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}"), "HIGH", "SendGrid API key"),
    SecretRule("TWILIO_SID", re.compile(r"AC[0-9a-fA-F]{32}"), "HIGH", "Twilio account SID"),
    SecretRule("MAILGUN_KEY", re.compile(r"key-[0-9a-zA-Z]{32}"), "HIGH", "Mailgun API key"),
    SecretRule("AZURE_STORAGE", re.compile(r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}"), "CRITICAL", "Azure storage connection string"),
    SecretRule("HIGH_ENTROPY_STRING", re.compile(r'(?i)(?:key|secret|token|password)\s*[=:]\s*["\'][A-Za-z0-9+/=_\-]{32,}["\']'), "MEDIUM", "High-entropy string in variable"),
)

# File extensions to scan
SCAN_EXTENSIONS: frozenset[str] = frozenset({
    ".py", ".js", ".ts", ".jsx", ".tsx", ".rb", ".go", ".java", ".cs", ".php",
    ".env", ".env.local", ".config", ".cfg", ".ini", ".yaml", ".yml", ".json",
    ".toml", ".xml", ".sh", ".bash", ".zsh", ".ps1", ".tf", ".tfvars",
    ".properties", ".conf", ".pem", ".key", ".crt",
})

# Paths/patterns to skip
SKIP_PATHS: frozenset[str] = frozenset({
    ".git", "node_modules", "__pycache__", ".pytest_cache", "venv", ".venv",
    "dist", "build", ".tox", "coverage", "htmlcov",
})

# Allowlist patterns (test fixtures, documentation examples)
_ALLOWLIST_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)(example|sample|test|fake|dummy|placeholder|your[_\-]?api[_\-]?key|xxxx|aaaa|1234)", re.IGNORECASE),
    re.compile(r"(?i)#\s*(noqa|nosec|pragma|secret-scanner-disable)"),
)

MAX_LINE_LENGTH = 2000  # skip excessively long lines (minified JS, base64 blobs)


# ── Finding ────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class SecretFinding:
    """A potential secret found in a file."""

    rule_name: str
    severity: str
    description: str
    file_path: str
    line_number: int
    line_content: str
    matched_value: str
    mitre_technique: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "rule_name": self.rule_name,
            "severity": self.severity,
            "description": self.description,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "line_content": self.line_content[:200],
            "matched_value": _redact(self.matched_value),
            "mitre_technique": self.mitre_technique,
        }


def _redact(value: str, show_chars: int = 4) -> str:
    """Partially redact a secret value for safe display."""
    if len(value) <= show_chars * 2:
        return "*" * len(value)
    return value[:show_chars] + "..." + value[-show_chars:]


def _is_allowlisted(line: str) -> bool:
    """Return True if the line matches an allowlist pattern."""
    return any(p.search(line) for p in _ALLOWLIST_PATTERNS)


# ── Scanner ────────────────────────────────────────────────────────────────────

@dataclass
class ScanResult:
    """Results for a single file scan."""

    file_path: str
    findings: list[SecretFinding]
    lines_scanned: int
    skipped: bool = False
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "file_path": self.file_path,
            "findings_count": len(self.findings),
            "lines_scanned": self.lines_scanned,
            "findings": [f.to_dict() for f in self.findings],
            "error": self.error,
        }


class SecretsScanner:
    """Scans files and directories for hardcoded secrets."""

    def __init__(
        self,
        rules: tuple[SecretRule, ...] | None = None,
        extra_extensions: set[str] | None = None,
    ) -> None:
        self._rules = rules if rules is not None else BUILTIN_RULES
        self._extensions = SCAN_EXTENSIONS | (extra_extensions or set())

    def scan_file(self, file_path: Path) -> ScanResult:
        """Scan a single file for secrets."""
        findings: list[SecretFinding] = []
        lines_scanned = 0
        try:
            with file_path.open(errors="replace") as fh:
                for lineno, line in enumerate(fh, 1):
                    line = line.rstrip("\n")
                    if len(line) > MAX_LINE_LENGTH:
                        continue
                    lines_scanned += 1
                    if _is_allowlisted(line):
                        continue
                    for rule in self._rules:
                        m = rule.pattern.search(line)
                        if m:
                            findings.append(SecretFinding(
                                rule_name=rule.name,
                                severity=rule.severity,
                                description=rule.description,
                                file_path=str(file_path),
                                line_number=lineno,
                                line_content=line.strip(),
                                matched_value=m.group(),
                                mitre_technique=rule.mitre_technique,
                            ))
                            break  # one finding per line
        except OSError as exc:
            return ScanResult(file_path=str(file_path), findings=[], lines_scanned=0, error=str(exc))
        return ScanResult(file_path=str(file_path), findings=findings, lines_scanned=lines_scanned)

    def scan_directory(
        self, root: Path, recursive: bool = True
    ) -> Iterator[ScanResult]:
        """Scan all eligible files in a directory."""
        pattern = "**/*" if recursive else "*"
        for path in root.glob(pattern):
            if path.is_file() and self._should_scan(path):
                yield self.scan_file(path)

    def _should_scan(self, path: Path) -> bool:
        """Return True if the file should be scanned."""
        parts = set(path.parts)
        if parts & SKIP_PATHS:
            return False
        return path.suffix.lower() in self._extensions or path.name.startswith(".env")


@dataclass
class BatchScanSummary:
    """Summary of a batch scan."""

    total_files: int
    files_with_findings: int
    total_findings: int
    by_severity: dict[str, int]
    results: list[ScanResult]

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "total_files": self.total_files,
            "files_with_findings": self.files_with_findings,
            "total_findings": self.total_findings,
            "by_severity": self.by_severity,
            "results": [r.to_dict() for r in self.results if r.findings],
        }


def batch_scan(scanner: SecretsScanner, root: Path, recursive: bool = True) -> BatchScanSummary:
    """Scan a directory and return a batch summary."""
    results: list[ScanResult] = []
    by_severity: dict[str, int] = {}
    for result in scanner.scan_directory(root, recursive=recursive):
        results.append(result)
        for finding in result.findings:
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
    files_with_findings = sum(1 for r in results if r.findings)
    total_findings = sum(len(r.findings) for r in results)
    return BatchScanSummary(
        total_files=len(results),
        files_with_findings=files_with_findings,
        total_findings=total_findings,
        by_severity=by_severity,
        results=results,
    )
