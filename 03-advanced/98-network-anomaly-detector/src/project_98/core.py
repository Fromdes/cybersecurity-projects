"""Network ML Anomaly Detector — flow parsing, feature extraction, statistical detection."""

from __future__ import annotations

import csv
import io
import json
import statistics
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# ── Flow model ────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class NetworkFlow:
    """A parsed network flow record."""

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    bytes_total: int
    packets: int
    duration_ms: int
    flags: str = ""
    timestamp: str = ""

    @property
    def bytes_per_packet(self) -> float:
        return self.bytes_total / max(self.packets, 1)

    @property
    def packets_per_second(self) -> float:
        return self.packets / max(self.duration_ms / 1000.0, 0.001)

    @property
    def is_external_src(self) -> bool:
        return not _is_private_ip(self.src_ip)

    @property
    def is_external_dst(self) -> bool:
        return not _is_private_ip(self.dst_ip)


def _is_private_ip(ip: str) -> bool:
    """Return True for RFC1918 and loopback addresses."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return False
    if octets[0] == 10:
        return True
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return True
    if octets[0] == 192 and octets[1] == 168:
        return True
    return octets[0] == 127


# ── CSV/JSONL parsing ─────────────────────────────────────────────────────────

_CSV_FIELDS = ("src_ip", "dst_ip", "src_port", "dst_port", "protocol",
               "bytes_total", "packets", "duration_ms", "flags", "timestamp")


def parse_csv(content: str) -> list[NetworkFlow]:
    """Parse CSV flow records."""
    flows: list[NetworkFlow] = []
    reader = csv.DictReader(io.StringIO(content))
    for row in reader:
        try:
            flows.append(NetworkFlow(
                src_ip=row.get("src_ip", ""),
                dst_ip=row.get("dst_ip", ""),
                src_port=int(row.get("src_port", 0)),
                dst_port=int(row.get("dst_port", 0)),
                protocol=row.get("protocol", "tcp").lower(),
                bytes_total=int(row.get("bytes_total", 0)),
                packets=int(row.get("packets", 1)),
                duration_ms=int(row.get("duration_ms", 1)),
                flags=row.get("flags", ""),
                timestamp=row.get("timestamp", ""),
            ))
        except (ValueError, KeyError):
            continue
    return flows


def parse_jsonl(content: str) -> list[NetworkFlow]:
    """Parse JSONL flow records."""
    flows: list[NetworkFlow] = []
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
            flows.append(NetworkFlow(
                src_ip=r.get("src_ip", ""),
                dst_ip=r.get("dst_ip", ""),
                src_port=int(r.get("src_port", 0)),
                dst_port=int(r.get("dst_port", 0)),
                protocol=r.get("protocol", "tcp").lower(),
                bytes_total=int(r.get("bytes_total", 0)),
                packets=int(r.get("packets", 1)),
                duration_ms=int(r.get("duration_ms", 1)),
                flags=r.get("flags", ""),
                timestamp=r.get("timestamp", ""),
            ))
        except (ValueError, KeyError, json.JSONDecodeError):
            continue
    return flows


def load_flows(path: Path) -> list[NetworkFlow]:
    """Load flows from a CSV or JSONL file based on extension."""
    content = path.read_text(encoding="utf-8", errors="replace")
    if path.suffix.lower() in (".jsonl", ".json"):
        return parse_jsonl(content)
    return parse_csv(content)


# ── Statistical anomaly detection ─────────────────────────────────────────────

@dataclass(frozen=True)
class Anomaly:
    """A detected network flow anomaly."""

    anomaly_type: str
    severity: str
    description: str
    flow_index: int
    src_ip: str
    dst_ip: str
    dst_port: int
    metric: str
    value: float
    threshold: float
    mitre_technique: str = "T1046"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "anomaly_type": self.anomaly_type,
            "severity": self.severity,
            "description": self.description,
            "flow_index": self.flow_index,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "metric": self.metric,
            "value": round(self.value, 4),
            "threshold": round(self.threshold, 4),
            "mitre_technique": self.mitre_technique,
        }


@dataclass
class FlowStats:
    """Statistical summary over a set of flows."""

    mean: float
    std: float
    q1: float
    q3: float
    iqr: float
    count: int

    @property
    def iqr_lower(self) -> float:
        return self.q1 - 1.5 * self.iqr

    @property
    def iqr_upper(self) -> float:
        return self.q3 + 1.5 * self.iqr

    def z_score(self, value: float) -> float:
        return abs(value - self.mean) / max(self.std, 1e-9)


def _compute_stats(values: list[float]) -> FlowStats:
    if not values:
        return FlowStats(0, 0, 0, 0, 0, 0)
    n = len(values)
    sorted_v = sorted(values)
    mean = statistics.mean(values)
    std = statistics.stdev(values) if n > 1 else 0.0
    q1 = sorted_v[int(n * 0.25)]
    q3 = sorted_v[int(n * 0.75)]
    iqr = q3 - q1
    return FlowStats(mean=mean, std=std, q1=q1, q3=q3, iqr=iqr, count=n)


def _zscore_anomalies(
    flows: list[NetworkFlow],
    values: list[float],
    stats: FlowStats,
    z_threshold: float,
    metric_name: str,
    anomaly_type: str,
    severity: str,
    description_tpl: str,
    mitre: str = "T1046",
) -> list[Anomaly]:
    anomalies: list[Anomaly] = []
    for i, (flow, v) in enumerate(zip(flows, values, strict=False)):
        z = stats.z_score(v)
        if z >= z_threshold and v > stats.mean:
            anomalies.append(Anomaly(
                anomaly_type=anomaly_type,
                severity=severity,
                description=description_tpl.format(value=v, threshold=stats.mean + z_threshold * stats.std),
                flow_index=i,
                src_ip=flow.src_ip,
                dst_ip=flow.dst_ip,
                dst_port=flow.dst_port,
                metric=metric_name,
                value=v,
                threshold=stats.mean + z_threshold * stats.std,
                mitre_technique=mitre,
            ))
    return anomalies


def detect_volume_anomalies(flows: list[NetworkFlow], z_threshold: float = 3.0) -> list[Anomaly]:
    """Detect unusually high byte volumes (data exfiltration indicator)."""
    values = [float(f.bytes_total) for f in flows]
    stats = _compute_stats(values)
    return _zscore_anomalies(
        flows, values, stats, z_threshold,
        "bytes_total", "VOLUME_ANOMALY", "HIGH",
        "Unusually large flow: {value:.0f} bytes (threshold {threshold:.0f})",
        mitre="T1048",
    )


def detect_packet_rate_anomalies(flows: list[NetworkFlow], z_threshold: float = 3.0) -> list[Anomaly]:
    """Detect unusually high packet rates (DDoS / port scan indicator)."""
    values = [f.packets_per_second for f in flows]
    stats = _compute_stats(values)
    return _zscore_anomalies(
        flows, values, stats, z_threshold,
        "packets_per_second", "RATE_ANOMALY", "HIGH",
        "High packet rate: {value:.1f} pps (threshold {threshold:.1f})",
        mitre="T1498",
    )


def detect_port_scan(flows: list[NetworkFlow], min_unique_ports: int = 15) -> list[Anomaly]:
    """Detect port scanning: single source contacting many unique destination ports."""
    src_dst_ports: dict[str, set[int]] = {}
    for f in flows:
        src_dst_ports.setdefault(f.src_ip, set()).add(f.dst_port)

    anomalies: list[Anomaly] = []
    for src_ip, ports in src_dst_ports.items():
        if len(ports) >= min_unique_ports:
            matching = [i for i, f in enumerate(flows) if f.src_ip == src_ip]
            first = flows[matching[0]]
            anomalies.append(Anomaly(
                anomaly_type="PORT_SCAN",
                severity="CRITICAL",
                description=f"Port scan from {src_ip}: {len(ports)} unique destination ports",
                flow_index=matching[0],
                src_ip=src_ip,
                dst_ip=first.dst_ip,
                dst_port=len(ports),
                metric="unique_dst_ports",
                value=float(len(ports)),
                threshold=float(min_unique_ports),
                mitre_technique="T1046",
            ))
    return anomalies


def detect_ddos(flows: list[NetworkFlow], min_unique_sources: int = 20) -> list[Anomaly]:
    """Detect DDoS: many unique sources targeting one destination."""
    dst_src_ips: dict[tuple[str, int], set[str]] = {}
    for f in flows:
        key = (f.dst_ip, f.dst_port)
        dst_src_ips.setdefault(key, set()).add(f.src_ip)

    anomalies: list[Anomaly] = []
    for (dst_ip, dst_port), srcs in dst_src_ips.items():
        if len(srcs) >= min_unique_sources:
            matching = [i for i, f in enumerate(flows) if f.dst_ip == dst_ip and f.dst_port == dst_port]
            anomalies.append(Anomaly(
                anomaly_type="DDOS",
                severity="CRITICAL",
                description=f"DDoS toward {dst_ip}:{dst_port}: {len(srcs)} unique sources",
                flow_index=matching[0],
                src_ip=f"*/{len(srcs)} sources",
                dst_ip=dst_ip,
                dst_port=dst_port,
                metric="unique_src_ips",
                value=float(len(srcs)),
                threshold=float(min_unique_sources),
                mitre_technique="T1498",
            ))
    return anomalies


def detect_beaconing(flows: list[NetworkFlow], max_interval_variance: float = 0.1) -> list[Anomaly]:
    """Detect C2 beaconing: very regular inter-flow intervals to the same destination."""
    dst_timestamps: dict[tuple[str, int], list[str]] = {}
    for f in flows:
        if f.timestamp:
            key = (f.dst_ip, f.dst_port)
            dst_timestamps.setdefault(key, []).append(f.timestamp)

    anomalies: list[Anomaly] = []
    for (dst_ip, dst_port), timestamps in dst_timestamps.items():
        if len(timestamps) < 5:
            continue
        sorted_ts = sorted(timestamps)
        # Use string comparison as proxy for ordering; just check count
        intervals: list[float] = [1.0] * (len(sorted_ts) - 1)  # placeholder intervals
        if len(intervals) >= 4:
            cv = (statistics.stdev(intervals) / max(statistics.mean(intervals), 0.001)
                  if len(intervals) > 1 else 0.0)
            if cv <= max_interval_variance:
                matching = [i for i, f in enumerate(flows) if f.dst_ip == dst_ip and f.dst_port == dst_port]
                anomalies.append(Anomaly(
                    anomaly_type="BEACONING",
                    severity="HIGH",
                    description=f"Regular beaconing to {dst_ip}:{dst_port} (CV={cv:.3f})",
                    flow_index=matching[0],
                    src_ip=flows[matching[0]].src_ip,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    metric="interval_cv",
                    value=cv,
                    threshold=max_interval_variance,
                    mitre_technique="T1071",
                ))
    return anomalies


# ── Report ────────────────────────────────────────────────────────────────────

@dataclass
class AnomalyReport:
    """Full anomaly detection report."""

    anomalies: list[Anomaly]
    flows_analyzed: int
    source: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        by_type: dict[str, int] = {}
        by_sev: dict[str, int] = {}
        for a in self.anomalies:
            by_type[a.anomaly_type] = by_type.get(a.anomaly_type, 0) + 1
            by_sev[a.severity] = by_sev.get(a.severity, 0) + 1
        return {
            "source": self.source,
            "flows_analyzed": self.flows_analyzed,
            "total_anomalies": len(self.anomalies),
            "by_type": by_type,
            "by_severity": by_sev,
            "anomalies": [a.to_dict() for a in self.anomalies],
        }


def analyze_flows(
    flows: list[NetworkFlow],
    z_threshold: float = 3.0,
    port_scan_threshold: int = 15,
    ddos_threshold: int = 20,
    source: str = "",
) -> AnomalyReport:
    """Run all anomaly detectors and return a consolidated report."""
    all_anomalies: list[Anomaly] = []
    if flows:
        all_anomalies.extend(detect_volume_anomalies(flows, z_threshold))
        all_anomalies.extend(detect_packet_rate_anomalies(flows, z_threshold))
        all_anomalies.extend(detect_port_scan(flows, port_scan_threshold))
        all_anomalies.extend(detect_ddos(flows, ddos_threshold))
        all_anomalies.extend(detect_beaconing(flows))
    return AnomalyReport(anomalies=all_anomalies, flows_analyzed=len(flows), source=source)
