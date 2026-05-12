"""ARP spoofing detector — monitors ARP traffic for IP-to-MAC binding conflicts."""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass, field
from typing import Final

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# ARP opcode values
ARP_REQUEST: Final[int] = 1
ARP_REPLY: Final[int] = 2

# Ethernet type
ETHERTYPE_ARP: Final[int] = 0x0806
ETHERTYPE_IP: Final[int] = 0x0800

ETHERNET_HEADER_SIZE: Final[int] = 14
ARP_PACKET_SIZE: Final[int] = 28      # hardware = Ethernet, protocol = IPv4

# PCAP
PCAP_MAGIC_LE: Final[bytes] = b"\xd4\xc3\xb2\xa1"
PCAP_MAGIC_BE: Final[bytes] = b"\xa1\xb2\xc3\xd4"
PCAP_GLOBAL_HEADER_SIZE: Final[int] = 24
PCAP_PACKET_HEADER_SIZE: Final[int] = 16
LINKTYPE_ETHERNET: Final[int] = 1

GRATUITOUS_ARP_THRESHOLD: Final[int] = 3   # N gratuitous ARPs from same MAC = suspicious
CONFLICT_WINDOW_SECONDS: Final[float] = 60.0


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ARPPacket:
    """A parsed ARP packet."""

    timestamp: float
    opcode: int          # 1 = request, 2 = reply
    sender_mac: str
    sender_ip: str
    target_mac: str
    target_ip: str
    eth_src: str         # Ethernet source MAC
    eth_dst: str         # Ethernet destination MAC

    @property
    def is_gratuitous(self) -> bool:
        """Return True if sender IP == target IP (gratuitous ARP)."""
        return self.sender_ip == self.target_ip

    @property
    def is_reply(self) -> bool:
        """Return True if ARP reply."""
        return self.opcode == ARP_REPLY


@dataclass(frozen=True)
class ARPConflict:
    """A detected IP-to-MAC mapping conflict."""

    timestamp: float
    ip_address: str
    old_mac: str
    new_mac: str
    packet: ARPPacket

    @property
    def severity(self) -> str:
        """Severity based on whether this is a gratuitous ARP reply."""
        if self.packet.is_gratuitous and self.packet.is_reply:
            return "critical"
        if self.packet.is_reply:
            return "high"
        return "medium"


@dataclass
class ARPTable:
    """Tracks IP-to-MAC bindings and detects conflicts."""

    _table: dict[str, str] = field(default_factory=dict)   # ip → mac
    conflicts: list[ARPConflict] = field(default_factory=list)
    gratuitous_counts: dict[str, int] = field(default_factory=dict)  # mac → count

    def update(self, packet: ARPPacket) -> ARPConflict | None:
        """Process an ARP packet and detect any conflicts.

        Args:
            packet: Parsed ARP packet.

        Returns:
            ARPConflict if a binding conflict is detected, else None.
        """
        ip = packet.sender_ip
        mac = packet.sender_mac

        if packet.is_gratuitous:
            self.gratuitous_counts[mac] = self.gratuitous_counts.get(mac, 0) + 1

        existing_mac = self._table.get(ip)
        if existing_mac is None:
            self._table[ip] = mac
            return None

        if existing_mac == mac:
            return None

        # MAC change detected — this is a conflict
        conflict = ARPConflict(
            timestamp=packet.timestamp,
            ip_address=ip,
            old_mac=existing_mac,
            new_mac=mac,
            packet=packet,
        )
        self._table[ip] = mac   # update to latest
        self.conflicts.append(conflict)
        return conflict

    def get_mac(self, ip: str) -> str | None:
        """Return the current MAC for an IP, or None if unknown."""
        return self._table.get(ip)

    def suspicious_macs(self, threshold: int = GRATUITOUS_ARP_THRESHOLD) -> list[str]:
        """Return MAC addresses that have sent >= threshold gratuitous ARPs."""
        return [mac for mac, count in self.gratuitous_counts.items() if count >= threshold]


# ---------------------------------------------------------------------------
# Frame parsers
# ---------------------------------------------------------------------------

def _mac_from_bytes(data: bytes, offset: int) -> str:
    """Format 6 bytes as colon-separated MAC."""
    return ":".join(f"{b:02x}" for b in data[offset: offset + 6])


def _ip_from_bytes(data: bytes, offset: int) -> str:
    """Format 4 bytes as dotted-decimal IP."""
    return ".".join(str(data[offset + i]) for i in range(4))


def parse_arp_packet(raw: bytes, timestamp: float = 0.0) -> ARPPacket | None:
    """Parse a raw Ethernet frame and extract ARP data.

    Args:
        raw: Raw Ethernet frame bytes.
        timestamp: Capture timestamp.

    Returns:
        ARPPacket or None if not ARP or frame too short.
    """
    if len(raw) < ETHERNET_HEADER_SIZE + ARP_PACKET_SIZE:
        return None

    eth_dst = _mac_from_bytes(raw, 0)
    eth_src = _mac_from_bytes(raw, 6)
    ethertype = struct.unpack_from("!H", raw, 12)[0]

    if ethertype != ETHERTYPE_ARP:
        return None

    arp = raw[ETHERNET_HEADER_SIZE:]

    hw_type, proto_type, hw_size, proto_size, opcode = struct.unpack_from("!HHBBH", arp, 0)

    if hw_type != 1 or proto_type != ETHERTYPE_IP or hw_size != 6 or proto_size != 4:
        return None

    sender_mac = _mac_from_bytes(arp, 8)
    sender_ip = _ip_from_bytes(arp, 14)
    target_mac = _mac_from_bytes(arp, 18)
    target_ip = _ip_from_bytes(arp, 24)

    return ARPPacket(
        timestamp=timestamp,
        opcode=opcode,
        sender_mac=sender_mac,
        sender_ip=sender_ip,
        target_mac=target_mac,
        target_ip=target_ip,
        eth_src=eth_src,
        eth_dst=eth_dst,
    )


# ---------------------------------------------------------------------------
# PCAP reader
# ---------------------------------------------------------------------------

def read_pcap_frames(data: bytes) -> list[tuple[float, bytes]]:
    """Read Ethernet frames from a PCAP file.

    Args:
        data: Raw bytes of the PCAP file.

    Returns:
        List of (timestamp, raw_ethernet_frame) tuples.
    """
    if len(data) < PCAP_GLOBAL_HEADER_SIZE:
        return []

    magic = data[:4]
    if magic == PCAP_MAGIC_LE:
        endian = "<"
    elif magic == PCAP_MAGIC_BE:
        endian = ">"
    else:
        return []

    _v1, _v2, _tz, _sig, _snap, network = struct.unpack_from(f"{endian}HHIIII", data, 4)
    if int(network) != LINKTYPE_ETHERNET:
        return []

    frames: list[tuple[float, bytes]] = []
    offset = PCAP_GLOBAL_HEADER_SIZE

    while offset + PCAP_PACKET_HEADER_SIZE <= len(data):
        ts_sec, ts_usec, incl_len, _orig_len = struct.unpack_from(f"{endian}IIII", data, offset)
        offset += PCAP_PACKET_HEADER_SIZE
        if offset + incl_len > len(data):
            break
        frames.append((ts_sec + ts_usec / 1_000_000, data[offset: offset + incl_len]))
        offset += incl_len

    return frames


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------

def analyse_pcap(data: bytes) -> ARPTable:
    """Analyse a PCAP file for ARP spoofing.

    Args:
        data: Raw PCAP file bytes.

    Returns:
        ARPTable with conflicts and gratuitous ARP counts.
    """
    table = ARPTable()
    frames = read_pcap_frames(data)

    for timestamp, raw in frames:
        packet = parse_arp_packet(raw, timestamp)
        if packet is not None:
            table.update(packet)

    return table


def analyse_arp_log(lines: list[str]) -> ARPTable:
    """Analyse arp/neigh command text output for static anomalies.

    Lines like: ``192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE``

    Args:
        lines: Lines from `ip neigh show` or similar.

    Returns:
        ARPTable showing any duplicate MAC-for-IP anomalies.
    """
    table = ARPTable()
    mac_to_ips: dict[str, list[str]] = {}
    ts = time.time()

    for line in lines:
        parts = line.split()
        if len(parts) < 5:
            continue
        ip = parts[0]
        # find 'lladdr' keyword
        try:
            idx = parts.index("lladdr")
        except ValueError:
            continue
        if idx + 1 >= len(parts):
            continue
        mac = parts[idx + 1]

        mac_to_ips.setdefault(mac, []).append(ip)

        fake_pkt = ARPPacket(
            timestamp=ts,
            opcode=ARP_REPLY,
            sender_mac=mac,
            sender_ip=ip,
            target_mac="00:00:00:00:00:00",
            target_ip="0.0.0.0",
            eth_src=mac,
            eth_dst="ff:ff:ff:ff:ff:ff",
        )
        table.update(fake_pkt)

    return table
