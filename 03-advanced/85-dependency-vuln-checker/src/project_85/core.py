"""Dependency Vulnerability Checker — queries OSV.dev API for known CVEs in dependencies."""

from __future__ import annotations

import json
import logging
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

OSV_API_URL = "https://api.osv.dev/v1/query"
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
REQUEST_TIMEOUT = 15  # seconds
MAX_BATCH_SIZE = 100


# ── Dependency ─────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Dependency:
    """A single dependency with name and version."""

    name: str
    version: str
    ecosystem: str  # e.g., PyPI, npm, Go, Maven

    def to_osv_query(self) -> dict[str, Any]:
        """Build an OSV API query for this dependency."""
        return {
            "version": self.version,
            "package": {"name": self.name, "ecosystem": self.ecosystem},
        }


# ── Vulnerability ──────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Vulnerability:
    """A vulnerability found for a dependency."""

    vuln_id: str
    summary: str
    severity: str
    cvss_score: float
    fixed_version: str
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "vuln_id": self.vuln_id,
            "summary": self.summary,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "fixed_version": self.fixed_version,
            "references": self.references[:3],
        }


@dataclass
class DependencyResult:
    """Vulnerability check result for a single dependency."""

    dependency: Dependency
    vulnerabilities: list[Vulnerability]
    error: str = ""

    @property
    def is_vulnerable(self) -> bool:
        """Return True if any vulnerabilities found."""
        return len(self.vulnerabilities) > 0

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "name": self.dependency.name,
            "version": self.dependency.version,
            "ecosystem": self.dependency.ecosystem,
            "vulnerable": self.is_vulnerable,
            "vuln_count": len(self.vulnerabilities),
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "error": self.error,
        }


# ── Parsers ────────────────────────────────────────────────────────────────────

def parse_requirements_txt(path: Path) -> list[Dependency]:
    """Parse a Python requirements.txt file."""
    deps: list[Dependency] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9_\-\.]+)\s*(?:==|>=|<=|~=|!=|>|<)\s*([A-Za-z0-9._*+\-]+)", line)
        if m:
            name = m.group(1).strip()
            version = m.group(2).strip().lstrip("=")
            deps.append(Dependency(name=name, version=version, ecosystem="PyPI"))
    return deps


def parse_package_json(path: Path) -> list[Dependency]:
    """Parse a Node.js package.json file."""
    data = json.loads(path.read_text())
    deps: list[Dependency] = []
    for section in ("dependencies", "devDependencies"):
        for name, version_spec in (data.get(section) or {}).items():
            version = version_spec.lstrip("^~>=<").split(" ")[0].strip()
            if version and version != "*":
                deps.append(Dependency(name=name, version=version, ecosystem="npm"))
    return deps


def parse_go_mod(path: Path) -> list[Dependency]:
    """Parse a Go go.mod file."""
    deps: list[Dependency] = []
    in_require = False
    for line in path.read_text().splitlines():
        line = line.strip()
        if line.startswith("require ("):
            in_require = True
            continue
        if in_require and line == ")":
            in_require = False
            continue
        if in_require or line.startswith("require "):
            parts = line.replace("require ", "").split()
            if len(parts) >= 2:
                name = parts[0]
                version = parts[1].lstrip("v")
                deps.append(Dependency(name=name, version=version, ecosystem="Go"))
    return deps


def detect_and_parse(path: Path) -> list[Dependency]:
    """Auto-detect manifest type and parse dependencies."""
    name = path.name.lower()
    if name in ("requirements.txt", "requirements-dev.txt", "requirements-test.txt"):
        return parse_requirements_txt(path)
    if name == "package.json":
        return parse_package_json(path)
    if name == "go.mod":
        return parse_go_mod(path)
    raise ValueError(f"Unsupported manifest file: {path.name}")


# ── OSV client ─────────────────────────────────────────────────────────────────

def _parse_severity(vuln_data: dict[str, Any]) -> tuple[str, float]:
    """Extract severity label and CVSS score from OSV vuln data."""
    severities = vuln_data.get("severity", [])
    for sev in severities:
        score_str = sev.get("score", "")
        if "CVSS:3" in score_str:
            m = re.search(r"/AV:[^/]+/.*?/([^/]+)$", score_str)
            try:
                # Try to extract base score from affected fields
                pass
            except Exception:
                pass
    # Try database_specific.severity
    db_specific = vuln_data.get("database_specific", {})
    severity_label = db_specific.get("severity", "UNKNOWN").upper()
    cvss_score = 0.0
    for sev in severities:
        if sev.get("type") == "CVSS_V3":
            score_str = sev.get("score", "")
            m = re.search(r"CVSS:3\.\d+/[^/]+/[^/]+/[^/]+/([0-9.]+)$", score_str)
            if m:
                try:
                    cvss_score = float(m.group(1))
                except ValueError:
                    pass
    return severity_label, cvss_score


def _extract_fixed_version(vuln_data: dict[str, Any]) -> str:
    """Extract the fixed version from OSV affected ranges."""
    for affected in vuln_data.get("affected", []):
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    return event["fixed"]
    return ""


def _extract_references(vuln_data: dict[str, Any]) -> list[str]:
    """Extract reference URLs from OSV vuln data."""
    refs = []
    for ref in vuln_data.get("references", []):
        url = ref.get("url", "")
        if url:
            refs.append(url)
    return refs[:5]


def query_osv_single(dep: Dependency) -> DependencyResult:
    """Query OSV API for a single dependency."""
    payload = json.dumps(dep.to_osv_query()).encode()
    req = urllib.request.Request(
        OSV_API_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:  # noqa: S310
            data = json.loads(resp.read())
    except urllib.error.URLError as exc:
        return DependencyResult(dependency=dep, vulnerabilities=[], error=str(exc))
    except json.JSONDecodeError as exc:
        return DependencyResult(dependency=dep, vulnerabilities=[], error=f"JSON parse error: {exc}")

    vulns: list[Vulnerability] = []
    for vuln_data in data.get("vulns", []):
        severity, cvss = _parse_severity(vuln_data)
        fixed = _extract_fixed_version(vuln_data)
        refs = _extract_references(vuln_data)
        vulns.append(Vulnerability(
            vuln_id=vuln_data.get("id", "UNKNOWN"),
            summary=vuln_data.get("summary", "")[:200],
            severity=severity,
            cvss_score=cvss,
            fixed_version=fixed,
            references=refs,
        ))
    return DependencyResult(dependency=dep, vulnerabilities=vulns)


def query_osv_batch(deps: list[Dependency]) -> list[DependencyResult]:
    """Query OSV API for multiple dependencies in batch."""
    results: list[DependencyResult] = []
    for i in range(0, len(deps), MAX_BATCH_SIZE):
        batch = deps[i:i + MAX_BATCH_SIZE]
        payload = json.dumps({"queries": [d.to_osv_query() for d in batch]}).encode()
        req = urllib.request.Request(
            OSV_BATCH_URL,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:  # noqa: S310
                data = json.loads(resp.read())
        except (urllib.error.URLError, json.JSONDecodeError) as exc:
            for dep in batch:
                results.append(DependencyResult(dependency=dep, vulnerabilities=[], error=str(exc)))
            continue
        for dep, result_data in zip(batch, data.get("results", [])):
            vulns: list[Vulnerability] = []
            for vuln_data in result_data.get("vulns", []):
                severity, cvss = _parse_severity(vuln_data)
                fixed = _extract_fixed_version(vuln_data)
                refs = _extract_references(vuln_data)
                vulns.append(Vulnerability(
                    vuln_id=vuln_data.get("id", "UNKNOWN"),
                    summary=vuln_data.get("summary", "")[:200],
                    severity=severity,
                    cvss_score=cvss,
                    fixed_version=fixed,
                    references=refs,
                ))
            results.append(DependencyResult(dependency=dep, vulnerabilities=vulns))
    return results


# ── Summary ────────────────────────────────────────────────────────────────────

@dataclass
class ScanSummary:
    """Summary of a dependency vulnerability scan."""

    total_deps: int
    vulnerable_count: int
    total_vulns: int
    results: list[DependencyResult]
    by_severity: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "total_dependencies": self.total_deps,
            "vulnerable_packages": self.vulnerable_count,
            "total_vulnerabilities": self.total_vulns,
            "by_severity": self.by_severity,
            "results": [r.to_dict() for r in self.results if r.is_vulnerable or r.error],
        }
