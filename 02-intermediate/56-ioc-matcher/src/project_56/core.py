"""IOC (Indicator of Compromise) matching engine."""

from __future__ import annotations

import csv
import hashlib
import ipaddress
import json
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from io import StringIO
from pathlib import Path
from typing import Any, Final

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants / patterns
# ---------------------------------------------------------------------------

_IPV4_RE: Final[re.Pattern[str]] = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)
_DOMAIN_RE: Final[re.Pattern[str]] = re.compile(
    r"\b(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}\b"
)
_MD5_RE: Final[re.Pattern[str]] = re.compile(r"\b[0-9a-fA-F]{32}\b")
_SHA1_RE: Final[re.Pattern[str]] = re.compile(r"\b[0-9a-fA-F]{40}\b")
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"\b[0-9a-fA-F]{64}\b")
_URL_RE: Final[re.Pattern[str]] = re.compile(
    r"https?://[^\s\"'>]+"
)
_EMAIL_RE: Final[re.Pattern[str]] = re.compile(
    r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"
)
_CVE_RE: Final[re.Pattern[str]] = re.compile(r"\bCVE-\d{4}-\d{4,}\b")


class IOCType(str, Enum):
    IPV4 = "ipv4"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"
    CVE = "cve"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class IOC:
    """A single Indicator of Compromise."""

    value: str
    ioc_type: IOCType
    source: str = ""
    confidence: int = 50      # 0-100
    tags: tuple[str, ...] = ()
    description: str = ""


@dataclass(frozen=True)
class MatchResult:
    """A match between an IOC and observed text/data."""

    ioc: IOC
    matched_in: str          # field / context where the match was found
    context: str = ""        # surrounding text


# ---------------------------------------------------------------------------
# IOC store
# ---------------------------------------------------------------------------

@dataclass
class IOCStore:
    """In-memory IOC repository indexed by type and value."""

    _store: dict[IOCType, dict[str, IOC]] = field(
        default_factory=lambda: {t: {} for t in IOCType}, repr=False
    )

    def add(self, ioc: IOC) -> None:
        """Add an IOC to the store."""
        key = ioc.value.lower()
        self._store[ioc.ioc_type][key] = ioc
        logger.debug("IOC added: %s (%s)", ioc.value, ioc.ioc_type.value)

    def add_many(self, iocs: list[IOC]) -> None:
        for ioc in iocs:
            self.add(ioc)

    def lookup(self, value: str, ioc_type: IOCType) -> IOC | None:
        """Exact match lookup."""
        return self._store[ioc_type].get(value.lower())

    def count(self) -> int:
        return sum(len(v) for v in self._store.values())

    # ------------------------------------------------------------------
    # Loaders
    # ------------------------------------------------------------------

    @classmethod
    def from_csv(cls, path: Path, *, source: str = "") -> "IOCStore":
        """Load IOCs from a CSV with columns: value, type[, confidence, tags, description]."""
        store = cls()
        with path.open(encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                try:
                    ioc_type = IOCType(row["type"].strip().lower())
                except (KeyError, ValueError):
                    continue
                ioc = IOC(
                    value=row.get("value", "").strip(),
                    ioc_type=ioc_type,
                    source=row.get("source", source).strip(),
                    confidence=int(row.get("confidence", 50)),
                    tags=tuple(t.strip() for t in row.get("tags", "").split(",") if t.strip()),
                    description=row.get("description", "").strip(),
                )
                store.add(ioc)
        return store

    @classmethod
    def from_json(cls, path: Path, *, source: str = "") -> "IOCStore":
        """Load IOCs from a JSON list of {value, type, ...} objects."""
        store = cls()
        data: list[dict[str, Any]] = json.loads(path.read_text(encoding="utf-8"))
        for item in data:
            try:
                ioc_type = IOCType(item["type"].lower())
            except (KeyError, ValueError):
                continue
            ioc = IOC(
                value=item.get("value", ""),
                ioc_type=ioc_type,
                source=item.get("source", source),
                confidence=int(item.get("confidence", 50)),
                tags=tuple(item.get("tags", [])),
                description=item.get("description", ""),
            )
            store.add(ioc)
        return store


# ---------------------------------------------------------------------------
# Extractor — pull IOC candidates from raw text
# ---------------------------------------------------------------------------

def extract_iocs_from_text(text: str) -> dict[IOCType, list[str]]:
    """Extract candidate IOC values from arbitrary text."""
    sha256_hits = set(_SHA256_RE.findall(text))
    sha1_hits = set(_SHA1_RE.findall(text)) - sha256_hits
    md5_hits = set(_MD5_RE.findall(text)) - sha256_hits - sha1_hits

    return {
        IOCType.IPV4: list(set(_IPV4_RE.findall(text))),
        IOCType.DOMAIN: list(set(_DOMAIN_RE.findall(text))),
        IOCType.URL: list(set(_URL_RE.findall(text))),
        IOCType.MD5: list(md5_hits),
        IOCType.SHA1: list(sha1_hits),
        IOCType.SHA256: list(sha256_hits),
        IOCType.EMAIL: list(set(_EMAIL_RE.findall(text))),
        IOCType.CVE: list(set(_CVE_RE.findall(text))),
    }


# ---------------------------------------------------------------------------
# Matcher
# ---------------------------------------------------------------------------

@dataclass
class IOCMatcher:
    """Match extracted IOC candidates against the IOC store."""

    store: IOCStore

    def match_text(self, text: str, source_label: str = "") -> list[MatchResult]:
        """Extract IOCs from text and match against store."""
        candidates = extract_iocs_from_text(text)
        results: list[MatchResult] = []
        for ioc_type, values in candidates.items():
            for val in values:
                ioc = self.store.lookup(val, ioc_type)
                if ioc:
                    # Grab surrounding context (±40 chars)
                    idx = text.lower().find(val.lower())
                    ctx = text[max(0, idx - 40): idx + len(val) + 40] if idx >= 0 else ""
                    results.append(MatchResult(ioc=ioc, matched_in=source_label, context=ctx))
        return results

    def match_log_file(self, log_path: Path) -> list[MatchResult]:
        """Match IOCs in every line of a log file."""
        results: list[MatchResult] = []
        with log_path.open(encoding="utf-8", errors="replace") as fh:
            for i, line in enumerate(fh, start=1):
                hits = self.match_text(line.rstrip(), source_label=f"{log_path.name}:{i}")
                results.extend(hits)
        return results
