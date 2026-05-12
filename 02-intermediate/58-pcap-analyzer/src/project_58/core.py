"""PCAP analysis engine: packet parsing, flow aggregation, anomaly detection."""

from __future__ import annotations

import logging
import struct
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PCAP_GLOBAL_HEADER_SIZE: Final[int] = 24
PCAP_PACKET_HEADER_SIZE: Final[int] = 16
PCAP_MAGIC_LE: Final[bytes] = b"\xd4\xc3\xb2\xa1"
PCAP_MAGIC_BE: Final[bytes] = b"\xa1\xb2\xc3\xd4"

ETHERTYPE_IPV4: Final[int] = 0x0800
PROTOCOL_TCP: Final[int] = 6
PROTOCOL_UDP: Final[int] = 17
PROTOCOL_ICMP: Final[int] = 1

WELL_KNOWN_PORTS: Final[dict[int, str]] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https",
    445: "smb", 3306: "mysql", 3389: "rdp", 8080: "http-alt",
}


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Packet:
    """Minimal parsed packet."""

    ts_sec: int
    ts_usec: int
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    payload_len: int
    tcp_flags: int = 0  # SYN=2, ACK=16, FIN=1, RST=4


@dataclass
class Flow:
    """Aggregated network flow (5-tuple)."""

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    packet_count: int = 0
    byte_count: int = 0
    first_seen: int = 0
    last_seen: int = 0


@dataclass
class PCAPStats:
    """Summary statistics for a PCAP file."""

    total_packets: int = 0
    total_bytes: int = 0
    duration_seconds: float = 0.0
    protocol_counts: dict[str, int] = field(default_factory=dict)
    top_talkers: list[tuple[str, int]] = field(default_factory=list)
    flows: list[Flow] = field(default_factory=list)
    anomalies: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def _ip_from_bytes(data: bytes, offset: int) -> str:
    return ".".join(str(b) for b in data[offset: offset + 4])


def _parse_packet(data: bytes, ts_sec: int, ts_usec: int) -> Packet | None:
    """Parse raw frame bytes into a Packet. Returns None if not parseable."""
    if len(data) < 14:
        return None

    # Ethernet header: 14 bytes; ethertype at offset 12
    ethertype = struct.unpack("!H", data[12:14])[0]
    if ethertype != ETHERTYPE_IPV4:
        return None

    ip_start = 14
    if len(data) < ip_start + 20:
        return None

    ihl = (data[ip_start] & 0x0F) * 4
    protocol = data[ip_start + 9]
    src_ip = _ip_from_bytes(data, ip_start + 12)
    dst_ip = _ip_from_bytes(data, ip_start + 16)
    ip_total_len = struct.unpack("!H", data[ip_start + 2: ip_start + 4])[0]
    payload_len = ip_total_len - ihl

    transport_start = ip_start + ihl
    src_port = dst_port = 0
    tcp_flags = 0

    if protocol == PROTOCOL_TCP and len(data) >= transport_start + 14:
        src_port, dst_port = struct.unpack("!HH", data[transport_start: transport_start + 4])
        tcp_flags = data[transport_start + 13]
    elif protocol == PROTOCOL_UDP and len(data) >= transport_start + 4:
        src_port, dst_port = struct.unpack("!HH", data[transport_start: transport_start + 4])

    return Packet(
        ts_sec=ts_sec, ts_usec=ts_usec,
        src_ip=src_ip, dst_ip=dst_ip,
        src_port=src_port, dst_port=dst_port,
        protocol=protocol, payload_len=payload_len,
        tcp_flags=tcp_flags,
    )


class PCAPReader:
    """Pure-Python PCAP reader (no scapy required)."""

    def __init__(self, path: Path) -> None:
        self._data = path.read_bytes()
        self._offset = 0
        self._swap = False
        self._parse_global_header()

    def _parse_global_header(self) -> None:
        magic = self._data[:4]
        if magic == PCAP_MAGIC_LE:
            self._swap = False
        elif magic == PCAP_MAGIC_BE:
            self._swap = True
        else:
            raise ValueError(f"Not a valid PCAP file (magic={magic.hex()})")
        self._offset = PCAP_GLOBAL_HEADER_SIZE

    def packets(self) -> list[Packet]:
        result: list[Packet] = []
        fmt = "<" if not self._swap else ">"
        while self._offset + PCAP_PACKET_HEADER_SIZE <= len(self._data):
            hdr = self._data[self._offset: self._offset + PCAP_PACKET_HEADER_SIZE]
            ts_sec, ts_usec, incl_len, _ = struct.unpack(f"{fmt}IIII", hdr)
            self._offset += PCAP_PACKET_HEADER_SIZE
            frame = self._data[self._offset: self._offset + incl_len]
            self._offset += incl_len
            pkt = _parse_packet(frame, ts_sec, ts_usec)
            if pkt:
                result.append(pkt)
        return result


# ---------------------------------------------------------------------------
# Analyser
# ---------------------------------------------------------------------------

class PCAPAnalyser:
    """Compute statistics and detect anomalies from a list of packets."""

    PORT_SCAN_THRESHOLD: Final[int] = 15

    def analyse(self, packets: list[Packet]) -> PCAPStats:
        stats = PCAPStats()
        if not packets:
            return stats

        stats.total_packets = len(packets)
        stats.total_bytes = sum(p.payload_len for p in packets)

        ts_min = min(p.ts_sec for p in packets)
        ts_max = max(p.ts_sec for p in packets)
        stats.duration_seconds = float(ts_max - ts_min)

        # Protocol counts
        proto_map = {PROTOCOL_TCP: "tcp", PROTOCOL_UDP: "udp", PROTOCOL_ICMP: "icmp"}
        for pkt in packets:
            name = proto_map.get(pkt.protocol, str(pkt.protocol))
            stats.protocol_counts[name] = stats.protocol_counts.get(name, 0) + 1

        # Per-IP byte counts → top talkers
        ip_bytes: dict[str, int] = defaultdict(int)
        for pkt in packets:
            ip_bytes[pkt.src_ip] += pkt.payload_len

        stats.top_talkers = sorted(ip_bytes.items(), key=lambda x: x[1], reverse=True)[:10]

        # Flow aggregation
        flow_map: dict[tuple, Flow] = {}
        for pkt in packets:
            key = (pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.protocol)
            if key not in flow_map:
                flow_map[key] = Flow(
                    src_ip=pkt.src_ip, dst_ip=pkt.dst_ip,
                    src_port=pkt.src_port, dst_port=pkt.dst_port,
                    protocol=pkt.protocol, first_seen=pkt.ts_sec,
                )
            fl = flow_map[key]
            fl.packet_count += 1
            fl.byte_count += pkt.payload_len
            fl.last_seen = pkt.ts_sec

        stats.flows = list(flow_map.values())

        # Anomaly detection
        self._detect_port_scan(packets, stats)
        self._detect_syn_flood(packets, stats)

        return stats

    def _detect_port_scan(self, packets: list[Packet], stats: PCAPStats) -> None:
        """Detect IPs contacting many distinct destination ports."""
        ip_ports: dict[str, set[int]] = defaultdict(set)
        for pkt in packets:
            if pkt.protocol == PROTOCOL_TCP:
                ip_ports[pkt.src_ip].add(pkt.dst_port)
        for ip, ports in ip_ports.items():
            if len(ports) >= self.PORT_SCAN_THRESHOLD:
                stats.anomalies.append(
                    f"PORT_SCAN: {ip} contacted {len(ports)} distinct ports"
                )

    def _detect_syn_flood(self, packets: list[Packet], stats: PCAPStats) -> None:
        """Detect SYN-only flood (TCP SYN without ACK)."""
        SYN = 0x02  # noqa: N806
        ACK = 0x10  # noqa: N806
        syn_counts: dict[str, int] = defaultdict(int)
        for pkt in packets:
            if pkt.protocol == PROTOCOL_TCP:
                is_syn_only = (pkt.tcp_flags & SYN) and not (pkt.tcp_flags & ACK)
                if is_syn_only:
                    syn_counts[pkt.src_ip] += 1
        for ip, count in syn_counts.items():
            if count >= 50:
                stats.anomalies.append(f"SYN_FLOOD: {ip} sent {count} SYN packets")
