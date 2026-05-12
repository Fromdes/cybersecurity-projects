"""Rogue DHCP server detector — identifies unauthorised DHCP servers in PCAP/log data."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Final

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DHCP_SERVER_PORT: Final[int] = 67
DHCP_CLIENT_PORT: Final[int] = 68

DHCP_MAGIC_COOKIE: Final[bytes] = b"\x63\x82\x53\x63"

# DHCP message types (option 53)
DHCP_DISCOVER: Final[int] = 1
DHCP_OFFER: Final[int] = 2
DHCP_REQUEST: Final[int] = 3
DHCP_ACK: Final[int] = 5
DHCP_NAK: Final[int] = 6

# DHCP option tags
OPT_SUBNET: Final[int] = 1
OPT_ROUTER: Final[int] = 3
OPT_DNS: Final[int] = 6
OPT_HOSTNAME: Final[int] = 12
OPT_MESSAGE_TYPE: Final[int] = 53
OPT_SERVER_ID: Final[int] = 54
OPT_LEASE_TIME: Final[int] = 51
OPT_END: Final[int] = 255
OPT_PAD: Final[int] = 0

DHCP_BOOTP_MIN_SIZE: Final[int] = 240   # fixed header (236) + magic cookie (4)
BOOTP_FIXED_SIZE: Final[int] = 236

# Ethernet / IP / UDP offsets for PCAP Ethernet link-type frames
ETH_HEADER_SIZE: Final[int] = 14
IP_HEADER_MIN: Final[int] = 20
UDP_HEADER_SIZE: Final[int] = 8

# PCAP
PCAP_MAGIC_LE: Final[bytes] = b"\xd4\xc3\xb2\xa1"
PCAP_MAGIC_BE: Final[bytes] = b"\xa1\xb2\xc3\xd4"
PCAP_GLOBAL_HEADER_SIZE: Final[int] = 24
PCAP_PACKET_HEADER_SIZE: Final[int] = 16
LINKTYPE_ETHERNET: Final[int] = 1

ETHERTYPE_IP: Final[int] = 0x0800
PROTO_UDP: Final[int] = 17


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DHCPPacket:
    """A parsed DHCP packet."""

    timestamp: float
    src_mac: str
    src_ip: str
    server_id: str          # option 54 — actual server identifier
    message_type: int       # option 53
    offered_ip: str         # yiaddr field
    router: str             # option 3
    dns_servers: list[str]
    lease_time: int         # seconds
    subnet_mask: str

    @property
    def is_offer(self) -> bool:
        """Return True if this is a DHCPOFFER."""
        return self.message_type == DHCP_OFFER

    @property
    def is_ack(self) -> bool:
        """Return True if this is a DHCPACK."""
        return self.message_type == DHCP_ACK


@dataclass(frozen=True)
class RogueDHCPAlert:
    """Alert for an unauthorised DHCP server."""

    timestamp: float
    server_ip: str
    server_mac: str
    message_type: int
    offered_ip: str
    severity: str   # "critical" or "high"
    reason: str


@dataclass
class DHCPMonitorState:
    """State for rogue DHCP detection."""

    authorised_servers: frozenset[str]   # set of authorised server IPs
    seen_servers: dict[str, str] = field(default_factory=dict)   # ip → mac
    alerts: list[RogueDHCPAlert] = field(default_factory=list)
    packets: list[DHCPPacket] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Option parser
# ---------------------------------------------------------------------------

def _ip_from_bytes(data: bytes, offset: int = 0) -> str:
    """Format 4 bytes as dotted decimal IP."""
    return ".".join(str(data[offset + i]) for i in range(4))


def _mac_from_bytes(data: bytes, offset: int = 0) -> str:
    """Format 6 bytes as colon-separated MAC."""
    return ":".join(f"{data[offset + i]:02x}" for i in range(6))


def parse_dhcp_options(data: bytes) -> dict[int, bytes]:
    """Parse DHCP options from the options field (after magic cookie).

    Args:
        data: Options bytes (not including the 4-byte magic cookie).

    Returns:
        Dict mapping option tag → option value bytes.
    """
    options: dict[int, bytes] = {}
    i = 0
    while i < len(data):
        tag = data[i]
        if tag == OPT_END:
            break
        if tag == OPT_PAD:
            i += 1
            continue
        if i + 1 >= len(data):
            break
        length = data[i + 1]
        if i + 2 + length > len(data):
            break
        options[tag] = data[i + 2: i + 2 + length]
        i += 2 + length
    return options


def parse_dhcp_packet(raw: bytes, timestamp: float = 0.0) -> DHCPPacket | None:
    """Parse a raw Ethernet frame and extract DHCP data.

    Args:
        raw: Raw Ethernet frame bytes.
        timestamp: Capture timestamp.

    Returns:
        DHCPPacket or None if frame is not a DHCP server message.
    """
    if len(raw) < ETH_HEADER_SIZE + IP_HEADER_MIN + UDP_HEADER_SIZE + DHCP_BOOTP_MIN_SIZE:
        return None

    ethertype = struct.unpack_from("!H", raw, 12)[0]
    if ethertype != ETHERTYPE_IP:
        return None

    eth_src = _mac_from_bytes(raw, 6)
    ip_offset = ETH_HEADER_SIZE
    ihl = (raw[ip_offset] & 0x0F) * 4
    proto = raw[ip_offset + 9]
    if proto != PROTO_UDP:
        return None

    src_ip = _ip_from_bytes(raw, ip_offset + 12)
    udp_offset = ip_offset + ihl

    src_port = struct.unpack_from("!H", raw, udp_offset)[0]
    dst_port = struct.unpack_from("!H", raw, udp_offset + 2)[0]

    # DHCP offers come from port 67 to port 68
    if src_port != DHCP_SERVER_PORT or dst_port != DHCP_CLIENT_PORT:
        return None

    bootp_offset = udp_offset + UDP_HEADER_SIZE
    if len(raw) < bootp_offset + DHCP_BOOTP_MIN_SIZE:
        return None

    bootp = raw[bootp_offset:]
    if bootp[236:240] != DHCP_MAGIC_COOKIE:
        return None

    yiaddr = _ip_from_bytes(bootp, 16)   # offered IP
    options = parse_dhcp_options(bootp[240:])

    msg_type_raw = options.get(OPT_MESSAGE_TYPE, b"")
    msg_type = msg_type_raw[0] if msg_type_raw else 0

    # Only process OFFER and ACK
    if msg_type not in {DHCP_OFFER, DHCP_ACK}:
        return None

    server_id_raw = options.get(OPT_SERVER_ID, b"")
    server_id = _ip_from_bytes(server_id_raw) if len(server_id_raw) >= 4 else src_ip

    router_raw = options.get(OPT_ROUTER, b"")
    router = _ip_from_bytes(router_raw) if len(router_raw) >= 4 else ""

    dns_raw = options.get(OPT_DNS, b"")
    dns_servers = [_ip_from_bytes(dns_raw, i) for i in range(0, len(dns_raw) - 3, 4)]

    lease_raw = options.get(OPT_LEASE_TIME, b"")
    lease_time = struct.unpack("!I", lease_raw)[0] if len(lease_raw) == 4 else 0

    subnet_raw = options.get(OPT_SUBNET, b"")
    subnet_mask = _ip_from_bytes(subnet_raw) if len(subnet_raw) >= 4 else ""

    return DHCPPacket(
        timestamp=timestamp,
        src_mac=eth_src,
        src_ip=src_ip,
        server_id=server_id,
        message_type=msg_type,
        offered_ip=yiaddr,
        router=router,
        dns_servers=dns_servers,
        lease_time=lease_time,
        subnet_mask=subnet_mask,
    )


# ---------------------------------------------------------------------------
# PCAP reader
# ---------------------------------------------------------------------------

def read_pcap_frames(data: bytes) -> list[tuple[float, bytes]]:
    """Read Ethernet frames from a PCAP file."""
    if len(data) < PCAP_GLOBAL_HEADER_SIZE:
        return []
    magic = data[:4]
    endian = "<" if magic == PCAP_MAGIC_LE else (">" if magic == PCAP_MAGIC_BE else None)
    if endian is None:
        return []
    _v1, _v2, _tz, _sig, _snap, network = struct.unpack_from(f"{endian}HHIIII", data, 4)
    if int(network) != LINKTYPE_ETHERNET:
        return []
    frames: list[tuple[float, bytes]] = []
    offset = PCAP_GLOBAL_HEADER_SIZE
    while offset + PCAP_PACKET_HEADER_SIZE <= len(data):
        ts_sec, ts_usec, incl_len, _orig = struct.unpack_from(f"{endian}IIII", data, offset)
        offset += PCAP_PACKET_HEADER_SIZE
        if offset + incl_len > len(data):
            break
        frames.append((ts_sec + ts_usec / 1_000_000, data[offset: offset + incl_len]))
        offset += incl_len
    return frames


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

def process_packet(packet: DHCPPacket, state: DHCPMonitorState) -> RogueDHCPAlert | None:
    """Check a DHCP packet against the authorised servers list.

    Args:
        packet: Parsed DHCP packet.
        state: Running monitor state.

    Returns:
        RogueDHCPAlert if the server is unauthorised, else None.
    """
    state.packets.append(packet)
    server_ip = packet.server_id

    if server_ip in state.authorised_servers:
        return None

    # Check for previously unknown server
    if server_ip not in state.seen_servers:
        state.seen_servers[server_ip] = packet.src_mac

    severity = "critical" if packet.is_offer else "high"
    reason = (
        f"DHCP {'OFFER' if packet.is_offer else 'ACK'} from unauthorised server {server_ip}"
    )
    alert = RogueDHCPAlert(
        timestamp=packet.timestamp,
        server_ip=server_ip,
        server_mac=packet.src_mac,
        message_type=packet.message_type,
        offered_ip=packet.offered_ip,
        severity=severity,
        reason=reason,
    )
    state.alerts.append(alert)
    return alert


def analyse_pcap(data: bytes, authorised_servers: list[str]) -> DHCPMonitorState:
    """Analyse a PCAP file for rogue DHCP servers.

    Args:
        data: Raw PCAP file bytes.
        authorised_servers: List of known-good DHCP server IPs.

    Returns:
        DHCPMonitorState with alerts.
    """
    state = DHCPMonitorState(authorised_servers=frozenset(authorised_servers))
    frames = read_pcap_frames(data)
    for ts, raw in frames:
        packet = parse_dhcp_packet(raw, ts)
        if packet is not None:
            process_packet(packet, state)
    return state
