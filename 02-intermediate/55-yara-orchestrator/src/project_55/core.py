"""YARA rule orchestrator: compile, scan files/directories, report matches."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Soft import: yara-python is optional (tests mock it)
# ---------------------------------------------------------------------------

try:
    import yara  # type: ignore[import]
    YARA_AVAILABLE = True
except ImportError:
    yara = None  # type: ignore[assignment]
    YARA_AVAILABLE = False


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RuleMatch:
    """A single YARA rule match result."""

    rule_name: str
    namespace: str
    tags: tuple[str, ...]
    meta: dict[str, Any]
    strings: list[tuple[int, str, bytes]]  # (offset, name, data)
    file_path: str


@dataclass
class ScanReport:
    """Result of scanning one or more files."""

    scanned_files: int = 0
    matched_files: int = 0
    matches: list[RuleMatch] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def add_match(self, match: RuleMatch) -> None:
        self.matches.append(match)

    def summary(self) -> str:
        return (
            f"Scanned {self.scanned_files} file(s) — "
            f"{self.matched_files} matched — "
            f"{len(self.matches)} rule hits — "
            f"{len(self.errors)} error(s)"
        )


# ---------------------------------------------------------------------------
# Rule loader
# ---------------------------------------------------------------------------

@dataclass
class RuleLoader:
    """Loads YARA rules from .yar/.yara files in a directory."""

    rules_dir: Path

    def list_rule_files(self) -> list[Path]:
        """Return all .yar / .yara files under rules_dir."""
        files: list[Path] = []
        for ext in ("*.yar", "*.yara"):
            files.extend(sorted(self.rules_dir.rglob(ext)))
        return files

    def compile(self) -> Any:
        """Compile all rules into a single yara.Rules object."""
        if not YARA_AVAILABLE:
            raise ImportError("yara-python is not installed. Run: pip install yara-python")

        rule_files = self.list_rule_files()
        if not rule_files:
            raise FileNotFoundError(f"No .yar/.yara files found in {self.rules_dir}")

        filepaths: dict[str, str] = {}
        for i, path in enumerate(rule_files):
            namespace = f"ns{i}_{path.stem}"
            filepaths[namespace] = str(path)

        compiled = yara.compile(filepaths=filepaths)
        logger.info("Compiled %d YARA rule file(s)", len(rule_files))
        return compiled


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

@dataclass
class YARAScanner:
    """Scan files against compiled YARA rules."""

    compiled_rules: Any  # yara.Rules
    timeout: int = 60

    def scan_file(self, file_path: Path) -> list[RuleMatch]:
        """Scan a single file. Returns list of RuleMatch."""
        matches: list[RuleMatch] = []
        try:
            raw_matches = self.compiled_rules.match(str(file_path), timeout=self.timeout)
        except Exception as exc:  # noqa: BLE001
            logger.warning("YARA scan error on %s: %s", file_path, exc)
            return []

        for m in raw_matches:
            strings_list: list[tuple[int, str, bytes]] = []
            for s in m.strings:
                if hasattr(s, "instances"):
                    for inst in s.instances:
                        strings_list.append((inst.offset, s.identifier, inst.matched_data))
                else:
                    strings_list.append((s[0], s[1], s[2]))  # type: ignore[index]

            matches.append(RuleMatch(
                rule_name=m.rule,
                namespace=m.namespace,
                tags=tuple(m.tags),
                meta=dict(m.meta),
                strings=strings_list,
                file_path=str(file_path),
            ))
        return matches

    def scan_directory(
        self,
        scan_dir: Path,
        *,
        recursive: bool = True,
        max_file_size_mb: int = 100,
    ) -> ScanReport:
        """Scan all files in a directory."""
        report = ScanReport()
        pattern = "**/*" if recursive else "*"
        for target in scan_dir.glob(pattern):
            if not target.is_file():
                continue
            file_size_mb = target.stat().st_size / (1024 * 1024)
            if file_size_mb > max_file_size_mb:
                logger.debug("Skipping large file: %s (%.1f MiB)", target, file_size_mb)
                continue

            report.scanned_files += 1
            matches = self.scan_file(target)
            if matches:
                report.matched_files += 1
                for m in matches:
                    report.add_match(m)

        return report


# ---------------------------------------------------------------------------
# Convenience: scan with inline rule text (no file needed)
# ---------------------------------------------------------------------------

def scan_bytes_with_rule(data: bytes, rule_text: str) -> list[RuleMatch]:
    """Scan *data* against an inline YARA rule string. Returns matches."""
    if not YARA_AVAILABLE:
        raise ImportError("yara-python is not installed.")

    rules = yara.compile(source=rule_text)
    raw_matches = rules.match(data=data)
    result: list[RuleMatch] = []
    for m in raw_matches:
        strings_list: list[tuple[int, str, bytes]] = []
        for s in m.strings:
            if hasattr(s, "instances"):
                for inst in s.instances:
                    strings_list.append((inst.offset, s.identifier, inst.matched_data))
            else:
                strings_list.append((s[0], s[1], s[2]))  # type: ignore[index]
        result.append(RuleMatch(
            rule_name=m.rule,
            namespace=m.namespace,
            tags=tuple(m.tags),
            meta=dict(m.meta),
            strings=strings_list,
            file_path="<bytes>",
        ))
    return result
