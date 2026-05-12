"""NetFlow v5/v9 and IPFIX record parser and traffic analyser."""

from __future__ import annotations

import struct
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Final

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NETFLOW_V5_HEADER_SIZE: Final[int] = 24
NETFLOW_V5_RECORD_SIZE: Final[int] = 48
NETFLOW_V5_VERSION: Final[int] = 5

PROTOCOL_NAMES: Final[dict[int, str]] = {
    1: "icmp", 6: "tcp", 17: "udp", 47: "gre", 50: "esp",
}

TCP_FLAGS: Final[dict[int, str]] = {
    0x01: "FIN", 0x02: "SYN", 0x04: "RST", 0x08: "PSH",
    0x10: "ACK", 0x20: "URG",
}


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class NetFlowRecord:
    """A single NetFlow v5 flow record."""

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    packets: int
    bytes_count: int
    first_ms: int    # SysUptime ms at flow start
    last_ms: int     # SysUptime ms at flow end
    tcp_flags: int
    tos: int

    @property
    def protocol_name(self) -> str:
        return PROTOCOL_NAMES.get(self.protocol, str(self.protocol))

    @property
    def duration_ms(self) -> int:
        return max(0, self.last_ms - self.first_ms)

    @property
    def tcp_flag_names(self) -> list[str]:
        return [name for bit, name in TCP_FLAGS.items() if self.tcp_flags & bit]


@dataclass
class NetFlowV5Packet:
    """Parsed NetFlow v5 UDP datagram."""

    version: int
    count: int
    sys_uptime: int
    unix_secs: int
    unix_nsecs: int
    flow_sequence: int
    records: list[NetFlowRecord] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def _ip_from_uint32(n: int) -> str:
    return ".".join(str((n >> (8 * i)) & 0xFF) for i in reversed(range(4)))


def parse_netflow_v5(data: bytes) -> NetFlowV5Packet | None:
    """Parse a NetFlow v5 UDP packet from raw bytes."""
    if len(data) < NETFLOW_V5_HEADER_SIZE:
        return None

    version, count, sys_uptime, unix_secs, unix_nsecs, flow_seq, engine_type, engine_id, sampling = \
        struct.unpack("!HHIIIIBBH", data[:NETFLOW_V5_HEADER_SIZE])

    if version != NETFLOW_V5_VERSION:
        return None

    packet = NetFlowV5Packet(
        version=version, count=count, sys_uptime=sys_uptime,
        unix_secs=unix_secs, unix_nsecs=unix_nsecs, flow_sequence=flow_seq,
    )

    for i in range(count):
        offset = NETFLOW_V5_HEADER_SIZE + i * NETFLOW_V5_RECORD_SIZE
        if offset + NETFLOW_V5_RECORD_SIZE > len(data):
            break
        record_data = data[offset: offset + NETFLOW_V5_RECORD_SIZE]
        record = _parse_v5_record(record_data)
        if record:
            packet.records.append(record)

    return packet


def _parse_v5_record(data: bytes) -> NetFlowRecord | None:
    """Parse a single 48-byte NetFlow v5 flow record."""
    if len(data) < NETFLOW_V5_RECORD_SIZE:
        return None
    # NetFlow v5 record: 48 bytes total; trailing 2 bytes are padding (xx = no values)
    (src_addr, dst_addr, nexthop, input_if, output_if,
     d_pkts, d_octets, first, last,
     src_port, dst_port, pad1, tcp_flags, proto, tos,
     src_as, dst_as, src_mask, dst_mask) = struct.unpack("!IIIHHIIIIHHBBBBHHBBxx", data)

    return NetFlowRecord(
        src_ip=_ip_from_uint32(src_addr),
        dst_ip=_ip_from_uint32(dst_addr),
        src_port=src_port,
        dst_port=dst_port,
        protocol=proto,
        packets=d_pkts,
        bytes_count=d_octets,
        first_ms=first,
        last_ms=last,
        tcp_flags=tcp_flags,
        tos=tos,
    )


# ---------------------------------------------------------------------------
# Analyser
# ---------------------------------------------------------------------------

@dataclass
class TrafficStats:
    """Aggregated traffic statistics from NetFlow records."""

    total_flows: int = 0
    total_packets: int = 0
    total_bytes: int = 0
    top_talkers: list[tuple[str, int]] = field(default_factory=list)
    top_destinations: list[tuple[str, int]] = field(default_factory=list)
    protocol_dist: dict[str, int] = field(default_factory=dict)
    port_dist: dict[int, int] = field(default_factory=dict)
    anomalies: list[str] = field(default_factory=list)


def analyse_records(records: list[NetFlowRecord]) -> TrafficStats:
    """Compute statistics and detect anomalies from a list of flow records."""
    stats = TrafficStats()
    if not records:
        return stats

    stats.total_flows = len(records)
    stats.total_packets = sum(r.packets for r in records)
    stats.total_bytes = sum(r.bytes_count for r in records)

    src_bytes: dict[str, int] = defaultdict(int)
    dst_bytes: dict[str, int] = defaultdict(int)
    proto_counts: dict[str, int] = defaultdict(int)
    dst_port_counts: dict[int, int] = defaultdict(int)

    for r in records:
        src_bytes[r.src_ip] += r.bytes_count
        dst_bytes[r.dst_ip] += r.bytes_count
        proto_counts[r.protocol_name] += 1
        dst_port_counts[r.dst_port] += 1

    stats.top_talkers = sorted(src_bytes.items(), key=lambda x: x[1], reverse=True)[:10]
    stats.top_destinations = sorted(dst_bytes.items(), key=lambda x: x[1], reverse=True)[:10]
    stats.protocol_dist = dict(proto_counts)
    stats.port_dist = dict(
        sorted(dst_port_counts.items(), key=lambda x: x[1], reverse=True)[:20]
    )

    # Anomaly: single source contacting many distinct destinations
    src_dsts: dict[str, set[str]] = defaultdict(set)
    for r in records:
        src_dsts[r.src_ip].add(r.dst_ip)
    for ip, dsts in src_dsts.items():
        if len(dsts) > 50:
            stats.anomalies.append(
                f"SCAN_CANDIDATE: {ip} contacted {len(dsts)} distinct IPs"
            )

    # Anomaly: high-volume single flow
    for r in records:
        if r.bytes_count > 100 * 1024 * 1024:
            stats.anomalies.append(
                f"LARGE_FLOW: {r.src_ip}→{r.dst_ip}:{r.dst_port} "
                f"{r.bytes_count // (1024 * 1024)} MiB"
            )

    return stats
