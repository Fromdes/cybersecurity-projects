"""Memory Dump IOC Extractor — regex-based IOC extraction from raw memory dumps."""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ── IOC patterns ───────────────────────────────────────────────────────────────

_IPV4_PATTERN = re.compile(
    rb"(?<!\d)((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?))(?!\d)"
)
_IPV6_PATTERN = re.compile(
    rb"(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4})"
)
_DOMAIN_PATTERN = re.compile(
    rb"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|gov|edu|co|ru|cn|de|uk|info|biz|xyz|tk|top|app|dev|sh|cc)[^a-zA-Z]"
)
_URL_PATTERN = re.compile(
    rb"https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{8,200}"
)
_MD5_PATTERN = re.compile(rb"[0-9a-fA-F]{32}")
_SHA1_PATTERN = re.compile(rb"[0-9a-fA-F]{40}")
_SHA256_PATTERN = re.compile(rb"[0-9a-fA-F]{64}")
_EMAIL_PATTERN = re.compile(
    rb"[a-zA-Z0-9._%+\-]{1,64}@[a-zA-Z0-9.\-]{1,255}\.[a-zA-Z]{2,6}"
)
_WINDOWS_PATH = re.compile(
    rb"[A-Za-z]:\\(?:[^\x00-\x1f\\/:*?\"<>|]{1,255}\\)*[^\x00-\x1f\\/:*?\"<>|]{0,255}"
)
_REGISTRY_KEY = re.compile(
    rb"(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU|HKEY_CLASSES_ROOT|HKCR)\\[^\x00\r\n]{4,120}"
)

# Private/loopback IPs to skip
_PRIVATE_IP_PATTERNS: tuple[re.Pattern[bytes], ...] = (
    re.compile(rb"^127\."),
    re.compile(rb"^10\."),
    re.compile(rb"^192\.168\."),
    re.compile(rb"^172\.(1[6-9]|2\d|3[01])\."),
    re.compile(rb"^0\.0\.0\.0$"),
    re.compile(rb"^255\."),
)

CHUNK_SIZE = 1024 * 1024  # 1 MB chunks for streaming


# ── IOC types ──────────────────────────────────────────────────────────────────

IOC_TYPES = (
    "ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256",
    "email", "windows_path", "registry_key",
)


@dataclass(frozen=True)
class IOC:
    """An extracted indicator of compromise."""

    ioc_type: str
    value: str
    offset: int
    count: int = 1

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "ioc_type": self.ioc_type,
            "value": self.value,
            "offset": self.offset,
            "count": self.count,
        }


@dataclass
class ExtractionResult:
    """Full extraction result for a memory dump."""

    file_path: str
    file_size: int
    sha256: str
    iocs: dict[str, list[str]]
    total_count: int
    chunk_count: int

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "file_path": self.file_path,
            "file_size": self.file_size,
            "sha256": self.sha256,
            "total_ioc_count": self.total_count,
            "iocs": {k: sorted(set(v)) for k, v in self.iocs.items()},
        }


# ── Filtering helpers ──────────────────────────────────────────────────────────

def _is_private_ip(ip: bytes) -> bool:
    return any(p.match(ip) for p in _PRIVATE_IP_PATTERNS)


def _looks_like_hash_text(val: bytes) -> bool:
    """Skip sequences that are likely not real hashes (all same char, mostly digits)."""
    unique = set(val.lower())
    if len(unique) < 4:
        return False
    digit_count = sum(1 for b in val if 48 <= b <= 57)
    return digit_count < len(val) * 0.9


# ── Extractor ─────────────────────────────────────────────────────────────────

class IOCExtractor:
    """Extracts IOCs from binary data (memory dumps, disk images, log files)."""

    def extract_from_bytes(self, data: bytes) -> dict[str, set[str]]:
        """Extract all IOC types from a byte buffer."""
        result: dict[str, set[str]] = {t: set() for t in IOC_TYPES}

        for m in _IPV4_PATTERN.finditer(data):
            ip = m.group(1)
            if not _is_private_ip(ip):
                result["ipv4"].add(ip.decode("ascii", errors="replace"))

        for m in _IPV6_PATTERN.finditer(data):
            result["ipv6"].add(m.group().decode("ascii", errors="replace"))

        for m in _URL_PATTERN.finditer(data):
            result["url"].add(m.group().decode("ascii", errors="replace").rstrip())

        for m in _DOMAIN_PATTERN.finditer(data):
            val = m.group()[:-1].decode("ascii", errors="replace")
            result["domain"].add(val)

        for m in _EMAIL_PATTERN.finditer(data):
            result["email"].add(m.group().decode("ascii", errors="replace"))

        for m in _SHA256_PATTERN.finditer(data):
            if _looks_like_hash_text(m.group()):
                result["sha256"].add(m.group().decode("ascii"))

        for m in _SHA1_PATTERN.finditer(data):
            if _looks_like_hash_text(m.group()):
                result["sha1"].add(m.group().decode("ascii"))

        for m in _MD5_PATTERN.finditer(data):
            if _looks_like_hash_text(m.group()):
                result["md5"].add(m.group().decode("ascii"))

        for m in _WINDOWS_PATH.finditer(data):
            val = m.group().decode("latin-1", errors="replace")
            if len(val) >= 6:
                result["windows_path"].add(val)

        for m in _REGISTRY_KEY.finditer(data):
            result["registry_key"].add(m.group().decode("latin-1", errors="replace"))

        return result

    def extract_from_file(self, file_path: Path, max_size_gb: float = 4.0) -> ExtractionResult:
        """Extract IOCs from a file using streaming chunked reads."""
        file_size = file_path.stat().st_size
        max_bytes = int(max_size_gb * 1024 ** 3)
        if file_size > max_bytes:
            raise ValueError(f"File {file_path.name} exceeds {max_size_gb}GB limit")

        combined: dict[str, set[str]] = {t: set() for t in IOC_TYPES}
        sha256 = hashlib.sha256()
        chunk_count = 0
        overlap = b""

        with file_path.open("rb") as fh:
            while True:
                chunk = fh.read(CHUNK_SIZE)
                if not chunk:
                    break
                sha256.update(chunk)
                # Overlap to catch IOCs spanning chunk boundaries
                data = overlap + chunk
                batch = self.extract_from_bytes(data)
                for ioc_type, values in batch.items():
                    combined[ioc_type].update(values)
                overlap = chunk[-256:]
                chunk_count += 1

        total = sum(len(v) for v in combined.values())
        return ExtractionResult(
            file_path=str(file_path),
            file_size=file_size,
            sha256=sha256.hexdigest(),
            iocs={k: list(v) for k, v in combined.items()},
            total_count=total,
            chunk_count=chunk_count,
        )
