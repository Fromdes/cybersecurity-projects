"""Port scan detection engine operating on firewall/access log lines."""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Final

# ---------------------------------------------------------------------------
# Log line parsers (iptables/ufw and generic access log formats)
# ---------------------------------------------------------------------------

# iptables: DPT=<port> SRC=<ip>
_IPTABLES_RE: Final[re.Pattern[str]] = re.compile(
    r"SRC=(?P<src>\d{1,3}(?:\.\d{1,3}){3}).*DPT=(?P<dpt>\d+)"
)
# ufw: SRC=<ip> DST=<ip> ... DPT=<port>
_UFW_RE = _IPTABLES_RE  # same pattern covers ufw

# Generic access log: <ip> - - [timestamp] ...
_ACCESS_RE: Final[re.Pattern[str]] = re.compile(
    r"(?P<src>\d{1,3}(?:\.\d{1,3}){3})\s+-\s+-\s+\[.*?\]\s+"
    r'"[A-Z]+\s+[^\s]+\s+HTTP/[\d.]+"\s+(?P<status>\d{3})'
)

# Nginx/Apache error log with connection refused → port probe indicator
_CONN_REFUSED_RE: Final[re.Pattern[str]] = re.compile(
    r"connect\(\) failed.*(?P<src>\d{1,3}(?:\.\d{1,3}){3}).*port (?P<dpt>\d+)"
)


def parse_connection_line(line: str) -> tuple[str, int] | None:
    """Extract (src_ip, dst_port) from a log line. Returns None if not parseable."""
    for pattern in (_IPTABLES_RE, _CONN_REFUSED_RE):
        m = pattern.search(line)
        if m:
            try:
                return m.group("src"), int(m.group("dpt"))
            except (IndexError, ValueError):
                continue
    return None


# ---------------------------------------------------------------------------
# Detection models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ScanAlert:
    """A detected port scan alert."""

    source_ip: str
    distinct_ports: int
    port_list: tuple[int, ...]
    scan_type: str  # "horizontal" | "vertical" | "sweep"
    severity: str   # "low" | "medium" | "high"


@dataclass
class ScanDetector:
    """Stateful engine that accumulates connection events and raises alerts."""

    port_threshold: int = 15
    window_seconds: float = 60.0

    # ip -> list of (timestamp_float, port)
    _events: dict[str, list[tuple[float, int]]] = field(
        default_factory=lambda: defaultdict(list), repr=False
    )

    def record(self, src_ip: str, dst_port: int, timestamp: float) -> None:
        """Record a connection attempt."""
        self._events[src_ip].append((timestamp, dst_port))

    def analyse(self, current_time: float) -> list[ScanAlert]:
        """Return scan alerts for IPs that exceed thresholds in the time window."""
        alerts: list[ScanAlert] = []
        window_start = current_time - self.window_seconds

        for src_ip, events in self._events.items():
            recent = [(ts, port) for ts, port in events if ts >= window_start]
            if not recent:
                continue
            ports = sorted({port for _, port in recent})
            if len(ports) >= self.port_threshold:
                severity = self._classify_severity(len(ports))
                scan_type = self._classify_type(ports)
                alerts.append(ScanAlert(
                    source_ip=src_ip,
                    distinct_ports=len(ports),
                    port_list=tuple(ports),
                    scan_type=scan_type,
                    severity=severity,
                ))

        return sorted(alerts, key=lambda a: a.distinct_ports, reverse=True)

    def reset(self, src_ip: str) -> None:
        """Clear recorded events for an IP (after alert processing)."""
        self._events.pop(src_ip, None)

    # ------------------------------------------------------------------

    def _classify_severity(self, port_count: int) -> str:
        if port_count >= 100:
            return "high"
        if port_count >= 30:
            return "medium"
        return "low"

    def _classify_type(self, ports: list[int]) -> str:
        if len(ports) >= 50:
            return "sweep"
        # Sequential ports → horizontal scan
        if ports == list(range(min(ports), max(ports) + 1)):
            return "horizontal"
        return "vertical"


# ---------------------------------------------------------------------------
# Log file analyser
# ---------------------------------------------------------------------------

def analyse_log_file(
    log_lines: list[str],
    *,
    port_threshold: int = 15,
    window_seconds: float = 60.0,
    base_timestamp: float = 0.0,
) -> list[ScanAlert]:
    """Parse a list of log lines and return any detected scan alerts.

    *base_timestamp* is used as the starting epoch time; lines are assumed
    to arrive in order, separated by 0.1 s each (simulated time).
    """
    detector = ScanDetector(
        port_threshold=port_threshold,
        window_seconds=window_seconds,
    )

    for i, line in enumerate(log_lines):
        parsed = parse_connection_line(line)
        if parsed is None:
            continue
        src, port = parsed
        detector.record(src, port, base_timestamp + i * 0.1)

    current_time = base_timestamp + len(log_lines) * 0.1
    return detector.analyse(current_time)
