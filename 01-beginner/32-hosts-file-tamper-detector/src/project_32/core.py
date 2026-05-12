"""Hosts file tamper detection via baseline comparison."""
from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

DEFAULT_HOSTS_PATH: Path = Path("/etc/hosts")
COMMENT_PATTERN: re.Pattern[str] = re.compile(r"^\s*#")
ENTRY_PATTERN: re.Pattern[str] = re.compile(
    r"^\s*(?P<ip>\S+)\s+(?P<hostname>\S+)(?:\s+(?P<aliases>.*))?$"
)


@dataclass(frozen=True)
class HostsEntry:
    """A single resolved mapping in /etc/hosts."""

    ip: str
    hostname: str
    aliases: tuple[str, ...]
    raw_line: str


@dataclass(frozen=True)
class TamperResult:
    """Comparison outcome between baseline and current hosts file."""

    hash_changed: bool
    added: tuple[str, ...]
    removed: tuple[str, ...]
    suspicious: tuple[str, ...]
    is_tampered: bool


SUSPICIOUS_REDIRECTS: frozenset[str] = frozenset({
    "google.com", "facebook.com", "github.com", "microsoft.com",
    "apple.com", "amazon.com", "paypal.com", "bankofamerica.com",
})


def parse_hosts(path: Path = DEFAULT_HOSTS_PATH) -> list[HostsEntry]:
    """Parse *path* into a list of :class:`HostsEntry`.

    Args:
        path: Path to the hosts file.

    Returns:
        Parsed entries (comments and blank lines are skipped).

    Raises:
        FileNotFoundError: If *path* does not exist.
        PermissionError: If *path* cannot be read.
    """
    entries: list[HostsEntry] = []
    text = path.read_text(encoding="utf-8")
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or COMMENT_PATTERN.match(stripped):
            continue
        m = ENTRY_PATTERN.match(stripped)
        if m:
            aliases_raw = m.group("aliases") or ""
            aliases = tuple(a for a in aliases_raw.split() if a)
            entries.append(HostsEntry(
                ip=m.group("ip"),
                hostname=m.group("hostname"),
                aliases=aliases,
                raw_line=line,
            ))
    return entries


def hash_file(path: Path = DEFAULT_HOSTS_PATH) -> str:
    """Compute SHA-256 hex digest of *path*.

    Args:
        path: Path to hash.

    Returns:
        Lowercase hex string.
    """
    data = path.read_bytes()
    return hashlib.sha256(data).hexdigest()


def save_baseline(path: Path = DEFAULT_HOSTS_PATH, baseline_path: Path = Path("hosts_baseline.json")) -> dict[str, object]:
    """Snapshot the current hosts file as a JSON baseline.

    Args:
        path: Hosts file to snapshot.
        baseline_path: Where to write the JSON baseline.

    Returns:
        The baseline dict (also written to *baseline_path*).
    """
    entries = parse_hosts(path)
    file_hash = hash_file(path)
    baseline: dict[str, object] = {
        "hash": file_hash,
        "entries": [
            {"ip": e.ip, "hostname": e.hostname, "aliases": list(e.aliases)}
            for e in entries
        ],
    }
    baseline_path.write_text(json.dumps(baseline, indent=2), encoding="utf-8")
    log.info("Baseline saved to %s (%d entries)", baseline_path, len(entries))
    return baseline


def load_baseline(baseline_path: Path = Path("hosts_baseline.json")) -> dict[str, object]:
    """Load a JSON baseline created by :func:`save_baseline`.

    Args:
        baseline_path: Path to the JSON baseline file.

    Returns:
        Baseline dict.

    Raises:
        FileNotFoundError: If *baseline_path* does not exist.
        ValueError: If the baseline is malformed.
    """
    text = baseline_path.read_text(encoding="utf-8")
    data = json.loads(text)
    if "hash" not in data or "entries" not in data:
        raise ValueError(f"Invalid baseline format in {baseline_path}")
    return data  # type: ignore[return-value]


def detect_tampering(
    baseline: dict[str, object],
    path: Path = DEFAULT_HOSTS_PATH,
) -> TamperResult:
    """Compare *baseline* against the current state of *path*.

    Args:
        baseline: Dict from :func:`load_baseline` or :func:`save_baseline`.
        path: Live hosts file to compare.

    Returns:
        :class:`TamperResult` describing what changed.
    """
    current_hash = hash_file(path)
    baseline_hash = str(baseline["hash"])
    hash_changed = current_hash != baseline_hash

    baseline_entries = {
        (e["ip"], e["hostname"])
        for e in baseline["entries"]  # type: ignore[index]
    }
    current_entries_list = parse_hosts(path)
    current_entries = {(e.ip, e.hostname) for e in current_entries_list}

    added_keys = current_entries - baseline_entries
    removed_keys = baseline_entries - current_entries

    added = tuple(f"{ip} → {host}" for ip, host in sorted(added_keys))
    removed = tuple(f"{ip} → {host}" for ip, host in sorted(removed_keys))

    suspicious = tuple(
        f"{ip} → {host} (high-value target redirected)"
        for ip, host in added_keys
        if _is_suspicious_redirect(ip, host)
    )

    is_tampered = hash_changed or bool(suspicious)
    return TamperResult(
        hash_changed=hash_changed,
        added=added,
        removed=removed,
        suspicious=suspicious,
        is_tampered=is_tampered,
    )


def _is_suspicious_redirect(ip: str, hostname: str) -> bool:
    if ip.startswith("127.") or ip == "0.0.0.0":
        return False
    for domain in SUSPICIOUS_REDIRECTS:
        if hostname == domain or hostname.endswith("." + domain):
            return True
    return False
