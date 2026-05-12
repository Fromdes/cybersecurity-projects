"""Listening port enumeration and risk-scoring engine."""
from __future__ import annotations

import logging
from dataclasses import dataclass

import psutil

log = logging.getLogger(__name__)

PRIVILEGED_PORT_MAX: int = 1023
HIGH_PORT_MIN: int = 49152

WELL_KNOWN_PORTS: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    6379: "redis",
    8080: "http-alt",
    27017: "mongodb",
}

DANGEROUS_PORTS: frozenset[int] = frozenset({23, 445, 3389, 6379, 27017})

SCORE_DANGEROUS_PORT: int = 50
SCORE_TELNET: int = 60
SCORE_WORLD_BIND: int = 30
SCORE_NO_PROCESS: int = 40
SCORE_HIGH_EPHEMERAL_SERVER: int = 20

RISK_HIGH: int = 50
RISK_MEDIUM: int = 25


@dataclass(frozen=True)
class PortEntry:
    """A single listening network endpoint with risk assessment."""

    port: int
    protocol: str
    local_address: str
    pid: int | None
    process_name: str
    username: str
    service_guess: str
    risk_score: int
    risk_level: str
    risk_flags: tuple[str, ...]


def list_listening_ports(protocol: str = "all") -> list[PortEntry]:
    """Enumerate all listening TCP/UDP ports with risk scores.

    Args:
        protocol: One of ``"tcp"``, ``"udp"``, or ``"all"``.

    Returns:
        List of :class:`PortEntry` sorted by risk_score descending.

    Raises:
        ValueError: If *protocol* is not a recognised value.
    """
    allowed = {"tcp", "udp", "all"}
    if protocol not in allowed:
        raise ValueError(f"protocol must be one of {allowed}, got {protocol!r}")

    kinds: list[str] = ["tcp", "udp"] if protocol == "all" else [protocol]
    results: list[PortEntry] = []

    for kind in kinds:
        for conn in psutil.net_connections(kind=kind):
            if conn.status not in ("LISTEN", "") and kind == "tcp":
                continue
            if kind == "tcp" and conn.status != "LISTEN":
                continue
            entry = _build_entry(conn, kind)
            if entry is not None:
                results.append(entry)

    seen: set[tuple[int, str]] = set()
    unique: list[PortEntry] = []
    for e in results:
        key = (e.port, e.protocol)
        if key not in seen:
            seen.add(key)
            unique.append(e)

    return sorted(unique, key=lambda e: e.risk_score, reverse=True)


def filter_by_risk(entries: list[PortEntry], min_level: str = "MEDIUM") -> list[PortEntry]:
    """Return entries at or above *min_level*.

    Args:
        entries: Full list from :func:`list_listening_ports`.
        min_level: ``"LOW"``, ``"MEDIUM"``, or ``"HIGH"``.

    Returns:
        Filtered list.

    Raises:
        ValueError: If *min_level* is invalid.
    """
    thresholds = {"LOW": 0, "MEDIUM": RISK_MEDIUM, "HIGH": RISK_HIGH}
    if min_level not in thresholds:
        raise ValueError(f"min_level must be one of {set(thresholds)}, got {min_level!r}")
    threshold = thresholds[min_level]
    return [e for e in entries if e.risk_score >= threshold]


def _build_entry(conn: psutil.sconn, protocol: str) -> PortEntry | None:
    try:
        laddr = conn.laddr
        if not laddr:
            return None
        port: int = laddr.port
        local_address: str = laddr.ip

        pid: int | None = conn.pid
        process_name = ""
        username = ""
        if pid:
            try:
                proc = psutil.Process(pid)
                process_name = proc.name()
                username = proc.username()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                process_name = "<access denied>"

        service_guess = WELL_KNOWN_PORTS.get(port, "unknown")
        score, flags = _compute_risk(port, local_address, pid, protocol)
        level = _score_to_level(score)

        return PortEntry(
            port=port,
            protocol=protocol,
            local_address=local_address,
            pid=pid,
            process_name=process_name,
            username=username,
            service_guess=service_guess,
            risk_score=score,
            risk_level=level,
            risk_flags=tuple(flags),
        )
    except (AttributeError, OSError):
        return None


def _compute_risk(
    port: int, local_address: str, pid: int | None, protocol: str
) -> tuple[int, list[str]]:
    score = 0
    flags: list[str] = []

    if port in DANGEROUS_PORTS:
        score += SCORE_DANGEROUS_PORT
        flags.append(f"port {port} is a known high-risk service port")

    if port == 23:
        score += SCORE_TELNET
        flags.append("telnet (port 23) transmits credentials in plaintext")

    if local_address in ("0.0.0.0", "::"):
        score += SCORE_WORLD_BIND
        flags.append("bound to all interfaces — reachable from network")

    if pid is None:
        score += SCORE_NO_PROCESS
        flags.append("no owning process found (may require root)")

    if port >= HIGH_PORT_MIN and protocol == "tcp":
        score += SCORE_HIGH_EPHEMERAL_SERVER
        flags.append(f"server listening on ephemeral port {port}")

    return score, flags


def _score_to_level(score: int) -> str:
    if score >= RISK_HIGH:
        return "HIGH"
    if score >= RISK_MEDIUM:
        return "MEDIUM"
    return "LOW"
