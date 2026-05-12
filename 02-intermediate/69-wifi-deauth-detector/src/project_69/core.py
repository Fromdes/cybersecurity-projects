"""WiFi deauthentication attack detector — analyses PCAP or live captures for deauth floods."""

from __future__ import annotations

import struct
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Final

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# IEEE 802.11 frame types / subtypes
DOT11_TYPE_MANAGEMENT: Final[int] = 0x00
DOT11_SUBTYPE_DEAUTH: Final[int] = 0x0C       # 12
DOT11_SUBTYPE_DISASSOC: Final[int] = 0x0A     # 10

# Deauth reason codes that suggest an attack
ATTACK_REASON_CODES: Final[frozenset[int]] = frozenset({1, 2, 3, 6, 7, 8})

DEAUTH_THRESHOLD_DEFAULT: Final[int] = 10   # deauths per window to declare attack
WINDOW_SECONDS_DEFAULT: Final[float] = 10.0

BROADCAST_MAC: Final[str] = "ff:ff:ff:ff:ff:ff"

# PCAP magic bytes
PCAP_MAGIC_LE: Final[bytes] = b"\xd4\xc3\xb2\xa1"
PCAP_MAGIC_BE: Final[bytes] = b"\xa1\xb2\xc3\xd4"
PCAP_GLOBAL_HEADER_SIZE: Final[int] = 24
PCAP_PACKET_HEADER_SIZE: Final[int] = 16

# Radiotap minimum size
RADIOTAP_MIN: Final[int] = 4

# 802.11 frame control byte indices
FC_OFFSET: Final[int] = 0


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Dot11Frame:
    """A parsed 802.11 management frame."""

    timestamp: float
    frame_type: int       # upper 2 bits of FC byte 0
    frame_subtype: int    # upper 4 bits of FC byte 0
    src_mac: str
    dst_mac: str
    bssid: str
    reason_code: int      # 0 if not present


@dataclass(frozen=True)
class DeauthEvent:
    """A single detected deauthentication or disassociation event."""

    timestamp: float
    attacker_mac: str     # source of the deauth frame
    victim_mac: str       # destination (ff:ff:ff:ff:ff:ff = broadcast)
    bssid: str
    reason_code: int
    is_broadcast: bool
    frame_subtype: int    # DEAUTH or DISASSOC


@dataclass
class DeauthAlarm:
    """An alarm triggered when deauth rate exceeds threshold."""

    src_mac: str
    bssid: str
    count: int
    window_start: float
    window_end: float
    broadcast_ratio: float  # fraction of deauths that were broadcast

    @property
    def severity(self) -> str:
        """Return 'high' if broadcast or large count, else 'medium'."""
        if self.broadcast_ratio > 0.5 or self.count >= 50:
            return "high"
        return "medium"


@dataclass
class DeauthDetectorState:
    """Running state for deauthentication detection."""

    threshold: int = DEAUTH_THRESHOLD_DEFAULT
    window_seconds: float = WINDOW_SECONDS_DEFAULT
    events: list[DeauthEvent] = field(default_factory=list)
    alarms: list[DeauthAlarm] = field(default_factory=list)


# ---------------------------------------------------------------------------
# MAC address helper
# ---------------------------------------------------------------------------

def _mac_from_bytes(data: bytes, offset: int) -> str:
    """Format 6 bytes starting at offset as a MAC address string."""
    return ":".join(f"{b:02x}" for b in data[offset: offset + 6])


# ---------------------------------------------------------------------------
# 802.11 frame parser
# ---------------------------------------------------------------------------

def parse_dot11_frame(data: bytes, timestamp: float = 0.0) -> Dot11Frame | None:
    """Parse a raw 802.11 frame (after radiotap header stripped).

    Args:
        data: Raw frame bytes starting at 802.11 frame control.
        timestamp: Capture timestamp.

    Returns:
        Dot11Frame or None if frame is too short or not a management frame.
    """
    if len(data) < 24:
        return None

    fc0 = data[0]
    fc1 = data[1]

    frame_type = (fc0 >> 2) & 0x03
    frame_subtype = (fc0 >> 4) & 0x0F

    if frame_type != DOT11_TYPE_MANAGEMENT:
        return None
    if frame_subtype not in {DOT11_SUBTYPE_DEAUTH, DOT11_SUBTYPE_DISASSOC}:
        return None

    dst_mac = _mac_from_bytes(data, 4)
    src_mac = _mac_from_bytes(data, 10)
    bssid = _mac_from_bytes(data, 16)

    reason_code = 0
    if len(data) >= 26:
        reason_code = struct.unpack_from("<H", data, 24)[0]

    return Dot11Frame(
        timestamp=timestamp,
        frame_type=frame_type,
        frame_subtype=frame_subtype,
        src_mac=src_mac,
        dst_mac=dst_mac,
        bssid=bssid,
        reason_code=reason_code,
    )


def strip_radiotap(data: bytes) -> bytes | None:
    """Strip the radiotap header and return remaining 802.11 frame.

    Args:
        data: Raw packet data including radiotap header.

    Returns:
        802.11 frame bytes or None if data is too short.
    """
    if len(data) < RADIOTAP_MIN + 4:
        return None
    # Radiotap header length is a little-endian uint16 at offset 2
    rt_len = struct.unpack_from("<H", data, 2)[0]
    if rt_len > len(data):
        return None
    return data[rt_len:]


# ---------------------------------------------------------------------------
# PCAP reader (802.11 / radiotap link type)
# ---------------------------------------------------------------------------

LINKTYPE_IEEE80211: Final[int] = 105
LINKTYPE_IEEE80211_RADIOTAP: Final[int] = 127


def read_pcap_frames(data: bytes) -> list[tuple[float, bytes]]:
    """Read packet data from a PCAP file.

    Args:
        data: Raw bytes of the PCAP file.

    Returns:
        List of (timestamp_seconds, raw_packet_bytes) tuples.
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

    _ver_major, _ver_minor, _thiszone, _sigfigs, _snaplen, network = struct.unpack_from(
        f"{endian}HHIIII", data, 4
    )

    if network not in {LINKTYPE_IEEE80211, LINKTYPE_IEEE80211_RADIOTAP}:
        return []

    frames: list[tuple[float, bytes]] = []
    offset = PCAP_GLOBAL_HEADER_SIZE

    while offset + PCAP_PACKET_HEADER_SIZE <= len(data):
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack_from(
            f"{endian}IIII", data, offset
        )
        offset += PCAP_PACKET_HEADER_SIZE

        if offset + incl_len > len(data):
            break

        pkt = data[offset: offset + incl_len]
        timestamp = ts_sec + ts_usec / 1_000_000
        frames.append((timestamp, pkt))
        offset += incl_len

    return frames


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

def process_frame(
    frame_data: bytes,
    timestamp: float,
    link_type: int,
    state: DeauthDetectorState,
) -> DeauthEvent | None:
    """Process a single captured frame and record any deauth event.

    Args:
        frame_data: Raw packet bytes.
        timestamp: Capture timestamp.
        link_type: PCAP link type constant.
        state: Running detector state (mutated in place).

    Returns:
        DeauthEvent if the frame is a deauth/disassoc, else None.
    """
    dot11_data = frame_data
    if link_type == LINKTYPE_IEEE80211_RADIOTAP:
        stripped = strip_radiotap(frame_data)
        if stripped is None:
            return None
        dot11_data = stripped

    frame = parse_dot11_frame(dot11_data, timestamp)
    if frame is None:
        return None

    event = DeauthEvent(
        timestamp=timestamp,
        attacker_mac=frame.src_mac,
        victim_mac=frame.dst_mac,
        bssid=frame.bssid,
        reason_code=frame.reason_code,
        is_broadcast=frame.dst_mac == BROADCAST_MAC,
        frame_subtype=frame.frame_subtype,
    )
    state.events.append(event)
    return event


def analyse_events(state: DeauthDetectorState) -> list[DeauthAlarm]:
    """Analyse accumulated events and generate alarms.

    Args:
        state: Detector state with events list.

    Returns:
        List of DeauthAlarm objects (also appended to state.alarms).
    """
    if not state.events:
        return []

    # Group events by (src_mac, bssid) within sliding windows
    buckets: dict[tuple[str, str], list[DeauthEvent]] = defaultdict(list)
    for event in state.events:
        buckets[(event.attacker_mac, event.bssid)].append(event)

    alarms: list[DeauthAlarm] = []
    for (src_mac, bssid), events in buckets.items():
        events_sorted = sorted(events, key=lambda e: e.timestamp)
        window_start = events_sorted[0].timestamp
        window_end = events_sorted[-1].timestamp
        count = len(events_sorted)

        if count < state.threshold:
            continue

        broadcast_count = sum(1 for e in events_sorted if e.is_broadcast)
        broadcast_ratio = broadcast_count / count if count else 0.0

        alarm = DeauthAlarm(
            src_mac=src_mac,
            bssid=bssid,
            count=count,
            window_start=window_start,
            window_end=window_end,
            broadcast_ratio=broadcast_ratio,
        )
        alarms.append(alarm)

    state.alarms.extend(alarms)
    return alarms


def analyse_pcap(
    data: bytes,
    *,
    threshold: int = DEAUTH_THRESHOLD_DEFAULT,
    window_seconds: float = WINDOW_SECONDS_DEFAULT,
) -> DeauthDetectorState:
    """Analyse a PCAP file for deauthentication attacks.

    Args:
        data: Raw PCAP file bytes.
        threshold: Deauth count to trigger alarm.
        window_seconds: Time window for counting (currently unused — full file scope).

    Returns:
        DeauthDetectorState with events and alarms populated.
    """
    state = DeauthDetectorState(threshold=threshold, window_seconds=window_seconds)

    if len(data) < PCAP_GLOBAL_HEADER_SIZE:
        return state

    magic = data[:4]
    endian = "<" if magic == PCAP_MAGIC_LE else ">"
    if magic not in {PCAP_MAGIC_LE, PCAP_MAGIC_BE}:
        return state

    _ver_major, _ver_minor, _tz, _sig, _snap, network = struct.unpack_from(
        f"{endian}HHIIII", data, 4
    )

    link_type = int(network)
    frames = read_pcap_frames(data)

    for timestamp, frame_data in frames:
        process_frame(frame_data, timestamp, link_type, state)

    analyse_events(state)
    return state
