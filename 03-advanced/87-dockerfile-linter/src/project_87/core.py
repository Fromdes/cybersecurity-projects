"""Dockerfile Linter & CIS Checker — static analysis of Dockerfiles against CIS benchmarks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class LintFinding:
    """A single linting / CIS check finding."""

    rule_id: str
    severity: str  # INFO / WARN / ERROR / CRITICAL
    title: str
    description: str
    line_number: int
    line_content: str
    cis_benchmark: str = ""
    mitre_technique: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "line_number": self.line_number,
            "line_content": self.line_content[:120],
            "cis_benchmark": self.cis_benchmark,
            "mitre_technique": self.mitre_technique,
        }


# ── Dockerfile parser ─────────────────────────────────────────────────────────

@dataclass
class DockerfileInstruction:
    """A parsed Dockerfile instruction."""

    line_number: int
    instruction: str
    arguments: str
    raw: str


def parse_dockerfile(path: Path) -> list[DockerfileInstruction]:
    """Parse Dockerfile into instruction objects, handling line continuations."""
    instructions: list[DockerfileInstruction] = []
    content = path.read_text()
    lines = content.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        lineno = i + 1
        if not line or line.startswith("#"):
            i += 1
            continue
        # Handle line continuations
        full_line = line
        while full_line.endswith("\\") and i + 1 < len(lines):
            full_line = full_line.rstrip("\\").rstrip() + " " + lines[i + 1].strip()
            i += 1
        parts = full_line.split(None, 1)
        if parts:
            instr = parts[0].upper()
            args = parts[1] if len(parts) > 1 else ""
            instructions.append(DockerfileInstruction(lineno, instr, args, full_line))
        i += 1
    return instructions


# ── CIS / security rules ──────────────────────────────────────────────────────

def check_no_root_user(instructions: list[DockerfileInstruction]) -> list[LintFinding]:
    """CIS 4.1 — Ensure a non-root user is set."""
    findings: list[LintFinding] = []
    has_user = any(i.instruction == "USER" and i.arguments.strip() not in ("root", "0") for i in instructions)
    if not has_user:
        last_from = next(
            (i for i in reversed(instructions) if i.instruction == "FROM"), None
        )
        lineno = last_from.line_number if last_from else 1
        findings.append(LintFinding(
            rule_id="CIS-4.1",
            severity="CRITICAL",
            title="No non-root USER set",
            description="Container runs as root by default. Add USER <nonroot> instruction.",
            line_number=lineno,
            line_content="",
            cis_benchmark="CIS Docker 4.1",
            mitre_technique="T1611",
        ))
    return findings


def check_no_latest_tag(instructions: list[DockerfileInstruction]) -> list[LintFinding]:
    """CIS 4.2 — Use specific image tags, not latest."""
    findings: list[LintFinding] = []
    for instr in instructions:
        if instr.instruction == "FROM":
            image = instr.arguments.split()[0]
            if image.endswith(":latest") or ":" not in image:
                findings.append(LintFinding(
                    rule_id="CIS-4.2",
                    severity="WARN",
                    title="Use of :latest or untagged base image",
                    description=f"Pin base image to a specific digest or version tag: {image}",
                    line_number=instr.line_number,
                    line_content=instr.raw,
                    cis_benchmark="CIS Docker 4.2",
                    mitre_technique="T1195.001",
                ))
    return findings


def check_no_secrets_in_env(instructions: list[DockerfileInstruction]) -> list[LintFinding]:
    """CIS 4.10 — Do not store secrets in ENV variables."""
    findings: list[LintFinding] = []
    _secret_pattern = re.compile(
        r"(?i)(password|secret|token|api_key|private_key|credential|auth)\s*=\s*\S+",
        re.IGNORECASE,
    )
    for instr in instructions:
        if instr.instruction in ("ENV", "ARG") and _secret_pattern.search(instr.arguments):
            findings.append(LintFinding(
                rule_id="CIS-4.10",
                severity="CRITICAL",
                title="Secret stored in ENV/ARG",
                description="Credentials should not be stored in ENV/ARG. Use Docker secrets or build-time secrets.",
                line_number=instr.line_number,
                line_content=instr.raw[:120],
                cis_benchmark="CIS Docker 4.10",
                mitre_technique="T1552",
            ))
    return findings


def check_no_privileged(instructions: list[DockerfileInstruction]) -> list[LintFinding]:
    """Detect ADD with URLs (prefer COPY) and dangerous capabilities."""
    findings: list[LintFinding] = []
    for instr in instructions:
        if instr.instruction == "ADD" and re.search(r"https?://", instr.arguments):
            findings.append(LintFinding(
                rule_id="DF-001",
                severity="WARN",
                title="ADD with URL — use RUN curl/wget instead",
                description="ADD with URLs is unpredictable; use RUN wget/curl for explicit control.",
                line_number=instr.line_number,
                line_content=instr.raw,
            ))
    return findings


def check_healthcheck(instructions: list[DockerfileInstruction]) -> list[LintFinding]:
    """Ensure HEALTHCHECK is defined."""
    has_healthcheck = any(i.instruction == "HEALTHCHECK" for i in instructions)
    if not has_healthcheck:
        return [LintFinding(
            rule_id="DF-002",
            severity="INFO",
            title="No HEALTHCHECK defined",
            description="Add HEALTHCHECK instruction for container health monitoring.",
            line_number=1,
            line_content="",
            cis_benchmark="CIS Docker 4.6",
        )]
    return []


def check_no_apt_upgrade(instructions: list[DockerfileInstruction]) -> list[LintFinding]:
    """Warn against unconstrained apt-get upgrade."""
    findings: list[LintFinding] = []
    for instr in instructions:
        if instr.instruction == "RUN" and re.search(r"apt-get\s+upgrade\b", instr.arguments):
            findings.append(LintFinding(
                rule_id="DF-003",
                severity="WARN",
                title="Unconstrained apt-get upgrade",
                description="apt-get upgrade can introduce unexpected package versions. Pin versions instead.",
                line_number=instr.line_number,
                line_content=instr.raw[:120],
            ))
    return findings


def check_no_sudo(instructions: list[DockerfileInstruction]) -> list[LintFinding]:
    """Detect sudo usage inside RUN commands."""
    findings: list[LintFinding] = []
    for instr in instructions:
        if instr.instruction == "RUN" and re.search(r"\bsudo\b", instr.arguments):
            findings.append(LintFinding(
                rule_id="DF-004",
                severity="WARN",
                title="sudo used inside RUN",
                description="sudo in containers indicates privilege escalation. Use USER or run as appropriate user.",
                line_number=instr.line_number,
                line_content=instr.raw[:120],
                mitre_technique="T1548",
            ))
    return findings


def check_no_curl_pipe_sh(instructions: list[DockerfileInstruction]) -> list[LintFinding]:
    """Detect curl/wget piped to shell."""
    findings: list[LintFinding] = []
    for instr in instructions:
        if instr.instruction == "RUN" and re.search(r"(curl|wget).+\|\s*(ba)?sh", instr.arguments):
            findings.append(LintFinding(
                rule_id="DF-005",
                severity="ERROR",
                title="curl/wget piped to shell",
                description="Downloading and executing scripts directly is a supply chain risk. Download, verify, then execute.",
                line_number=instr.line_number,
                line_content=instr.raw[:120],
                mitre_technique="T1105",
            ))
    return findings


def check_expose_privileged_port(instructions: list[DockerfileInstruction]) -> list[LintFinding]:
    """Warn if exposing privileged ports < 1024."""
    findings: list[LintFinding] = []
    for instr in instructions:
        if instr.instruction == "EXPOSE":
            for port_str in instr.arguments.split():
                port_num = port_str.split("/")[0]
                try:
                    if int(port_num) < 1024:
                        findings.append(LintFinding(
                            rule_id="DF-006",
                            severity="INFO",
                            title=f"Exposing privileged port {port_num}",
                            description="Privileged ports (<1024) require root. Consider using ports >=1024.",
                            line_number=instr.line_number,
                            line_content=instr.raw,
                        ))
                except ValueError:
                    pass
    return findings


ALL_CHECKS = (
    check_no_root_user,
    check_no_latest_tag,
    check_no_secrets_in_env,
    check_no_privileged,
    check_healthcheck,
    check_no_apt_upgrade,
    check_no_sudo,
    check_no_curl_pipe_sh,
    check_expose_privileged_port,
)


# ── Linter ────────────────────────────────────────────────────────────────────

@dataclass
class LintResult:
    """Full lint result for a Dockerfile."""

    file_path: str
    findings: list[LintFinding]
    instructions_count: int

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        by_sev: dict[str, int] = {}
        for f in self.findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        return {
            "file_path": self.file_path,
            "instructions_count": self.instructions_count,
            "total_findings": len(self.findings),
            "by_severity": by_sev,
            "findings": [f.to_dict() for f in self.findings],
        }


def lint_dockerfile(path: Path) -> LintResult:
    """Run all CIS checks against a Dockerfile."""
    instructions = parse_dockerfile(path)
    findings: list[LintFinding] = []
    for check in ALL_CHECKS:
        findings.extend(check(instructions))
    findings.sort(key=lambda f: (
        {"CRITICAL": 0, "ERROR": 1, "WARN": 2, "INFO": 3}.get(f.severity, 4),
        f.line_number,
    ))
    return LintResult(
        file_path=str(path),
        findings=findings,
        instructions_count=len(instructions),
    )
