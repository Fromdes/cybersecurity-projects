"""Threat Hunting Toolkit — rule-based log hunting with IOC correlation."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# ── Hunt rule model ───────────────────────────────────────────────────────────

@dataclass(frozen=True)
class HuntRule:
    """A single threat hunting rule."""

    rule_id: str
    name: str
    description: str
    severity: str
    mitre_technique: str
    patterns: list[str]
    field_patterns: dict[str, str]
    condition: str = "any"

    @property
    def compiled_patterns(self) -> list[re.Pattern[str]]:
        """Return compiled regex patterns."""
        return [re.compile(p, re.IGNORECASE) for p in self.patterns]

    @property
    def compiled_field_patterns(self) -> dict[str, re.Pattern[str]]:
        """Return compiled field-specific patterns."""
        return {k: re.compile(v, re.IGNORECASE) for k, v in self.field_patterns.items()}

    def matches_line(self, line: str) -> bool:
        """Return True if *line* matches this rule based on condition."""
        compiled = self.compiled_patterns
        if not compiled and not self.field_patterns:
            return False
        if self.condition == "all":
            return all(p.search(line) for p in compiled)
        return any(p.search(line) for p in compiled)

    def matches_record(self, record: dict[str, Any]) -> bool:
        """Return True if a structured record matches this rule."""
        line = json.dumps(record)
        if self.compiled_field_patterns:
            for field_name, pat in self.compiled_field_patterns.items():
                val = str(record.get(field_name, ""))
                if pat.search(val):
                    return True
        if self.compiled_patterns:
            return self.matches_line(line)
        return False


def load_rules_from_dict(data: dict[str, Any]) -> list[HuntRule]:
    """Parse hunt rules from a dict (loaded from JSON/YAML)."""
    rules: list[HuntRule] = []
    for r in data.get("rules", []):
        rules.append(HuntRule(
            rule_id=r["rule_id"],
            name=r["name"],
            description=r.get("description", ""),
            severity=r.get("severity", "MEDIUM"),
            mitre_technique=r.get("mitre_technique", "T1059"),
            patterns=r.get("patterns", []),
            field_patterns=r.get("field_patterns", {}),
            condition=r.get("condition", "any"),
        ))
    return rules


def load_rules_file(path: Path) -> list[HuntRule]:
    """Load hunt rules from a JSON file."""
    return load_rules_from_dict(json.loads(path.read_text(encoding="utf-8")))


# ── Built-in rules ────────────────────────────────────────────────────────────

BUILTIN_RULES: tuple[HuntRule, ...] = (
    HuntRule(
        rule_id="HUNT-001",
        name="PowerShell Encoded Command",
        description="PowerShell with base64-encoded command argument",
        severity="HIGH",
        mitre_technique="T1059.001",
        patterns=[r"-[Ee]nc(odedCommand)?\s+[A-Za-z0-9+/=]{20,}"],
        field_patterns={},
    ),
    HuntRule(
        rule_id="HUNT-002",
        name="Suspicious Download via curl/wget",
        description="curl or wget piped to shell execution",
        severity="CRITICAL",
        mitre_technique="T1059.004",
        patterns=[r"(curl|wget).+\|\s*(bash|sh|python|perl|ruby)"],
        field_patterns={},
    ),
    HuntRule(
        rule_id="HUNT-003",
        name="LSASS Memory Access",
        description="Access to LSASS process memory for credential dumping",
        severity="CRITICAL",
        mitre_technique="T1003.001",
        patterns=[r"lsass\.exe", r"MiniDump.*lsass", r"procdump.*lsass"],
        field_patterns={},
    ),
    HuntRule(
        rule_id="HUNT-004",
        name="Scheduled Task Creation",
        description="New scheduled task created via schtasks or cron",
        severity="MEDIUM",
        mitre_technique="T1053",
        patterns=[r"schtasks\s+/create", r"crontab\s+-[le]"],
        field_patterns={},
    ),
    HuntRule(
        rule_id="HUNT-005",
        name="Lateral Movement via PsExec/WMI",
        description="Remote execution tools associated with lateral movement",
        severity="HIGH",
        mitre_technique="T1021",
        patterns=[r"psexec", r"wmic\s+.+\s+process\s+call\s+create"],
        field_patterns={},
    ),
    HuntRule(
        rule_id="HUNT-006",
        name="Defense Evasion via Process Hollowing",
        description="Suspicious parent-child process relationships",
        severity="HIGH",
        mitre_technique="T1055.012",
        patterns=[r"VirtualAllocEx", r"WriteProcessMemory", r"CreateRemoteThread"],
        field_patterns={},
    ),
    HuntRule(
        rule_id="HUNT-007",
        name="DNS Tunneling Indicator",
        description="Unusually long DNS query names (potential tunneling)",
        severity="MEDIUM",
        mitre_technique="T1071.004",
        patterns=[r"[a-z0-9]{20,}\.[a-z0-9]{8,}\.(com|net|org|io)"],
        field_patterns={},
    ),
    HuntRule(
        rule_id="HUNT-008",
        name="Privilege Escalation via sudo",
        description="User escalation to root via sudo",
        severity="MEDIUM",
        mitre_technique="T1548.003",
        patterns=[r"sudo\s+.*(bash|sh|python|perl|su\b|chmod|chown)"],
        field_patterns={},
    ),
    HuntRule(
        rule_id="HUNT-009",
        name="Suspicious Network Connection",
        description="Outbound connection to known bad ports or Tor exit nodes",
        severity="HIGH",
        mitre_technique="T1090",
        patterns=[r":9050\b", r":9150\b", r"torrc", r"\.onion\b"],
        field_patterns={},
    ),
    HuntRule(
        rule_id="HUNT-010",
        name="Data Exfiltration via Cloud Storage",
        description="Uploads to cloud storage APIs",
        severity="MEDIUM",
        mitre_technique="T1567",
        patterns=[r"PUT\s+.+amazonaws\.com", r"PUT\s+.+blob\.core\.windows\.net",
                  r"rclone\s+copy", r"aws\s+s3\s+cp"],
        field_patterns={},
    ),
)


# ── Hunt result ───────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class HuntMatch:
    """A single rule match in a log file."""

    rule_id: str
    rule_name: str
    severity: str
    mitre_technique: str
    file_path: str
    line_number: int
    line_content: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "mitre_technique": self.mitre_technique,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "line_content": self.line_content[:200],
        }


# ── IOC matcher ───────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class IOC:
    """An Indicator of Compromise."""

    ioc_type: str
    value: str


def load_ioc_file(path: Path) -> list[IOC]:
    """Load IOCs from a JSONL file (one per line: {"type": "ip", "value": "..."})."""
    iocs: list[IOC] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
            iocs.append(IOC(ioc_type=d["type"], value=d["value"]))
        except (json.JSONDecodeError, KeyError):
            continue
    return iocs


def hunt_iocs_in_text(text: str, iocs: list[IOC]) -> list[tuple[IOC, int, str]]:
    """Scan text for IOC matches. Returns list of (ioc, line_number, line)."""
    matches: list[tuple[IOC, int, str]] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for ioc in iocs:
            if ioc.value.lower() in line.lower():
                matches.append((ioc, lineno, line))
    return matches


# ── Hunt engine ───────────────────────────────────────────────────────────────

_SKIP_EXTENSIONS: frozenset[str] = frozenset({".pyc", ".so", ".dll", ".exe", ".bin",
                                               ".jpg", ".png", ".pdf", ".zip", ".gz"})


def hunt_file(
    path: Path,
    rules: tuple[HuntRule, ...] | list[HuntRule] = BUILTIN_RULES,
) -> list[HuntMatch]:
    """Scan a single log file for hunt rule matches."""
    if path.suffix.lower() in _SKIP_EXTENSIONS:
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    matches: list[HuntMatch] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        for rule in rules:
            if rule.matches_line(line):
                matches.append(HuntMatch(
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    mitre_technique=rule.mitre_technique,
                    file_path=str(path),
                    line_number=lineno,
                    line_content=line.rstrip(),
                ))
    return matches


@dataclass
class HuntReport:
    """Full threat hunt report."""

    matches: list[HuntMatch]
    files_scanned: int
    rules_applied: int
    source: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        by_rule: dict[str, int] = {}
        by_sev: dict[str, int] = {}
        for m in self.matches:
            by_rule[m.rule_id] = by_rule.get(m.rule_id, 0) + 1
            by_sev[m.severity] = by_sev.get(m.severity, 0) + 1
        return {
            "source": self.source,
            "files_scanned": self.files_scanned,
            "rules_applied": self.rules_applied,
            "total_matches": len(self.matches),
            "by_rule": by_rule,
            "by_severity": by_sev,
            "matches": [m.to_dict() for m in self.matches],
        }


def hunt_directory(
    path: Path,
    rules: tuple[HuntRule, ...] | list[HuntRule] = BUILTIN_RULES,
) -> HuntReport:
    """Recursively hunt all log files in a directory."""
    all_matches: list[HuntMatch] = []
    scanned = 0
    for file_path in path.rglob("*"):
        if file_path.is_file() and file_path.suffix.lower() not in _SKIP_EXTENSIONS:
            all_matches.extend(hunt_file(file_path, rules))
            scanned += 1
    return HuntReport(
        matches=all_matches,
        files_scanned=scanned,
        rules_applied=len(rules),
        source=str(path),
    )
