"""Tests for project 69 WiFi Deauth Detector."""

from __future__ import annotations

import struct

import pytest

from project_69.core import (
    BROADCAST_MAC,
    DOT11_SUBTYPE_DEAUTH,
    DOT11_SUBTYPE_DISASSOC,
    LINKTYPE_IEEE80211,
    LINKTYPE_IEEE80211_RADIOTAP,
    PCAP_MAGIC_LE,
    DeauthDetectorState,
    DeauthEvent,
    _mac_from_bytes,
    analyse_events,
    analyse_pcap,
    parse_dot11_frame,
    process_frame,
    read_pcap_frames,
    strip_radiotap,
)


# ---------------------------------------------------------------------------
# Synthetic frame builders
# ---------------------------------------------------------------------------

def _mac_bytes(mac: str) -> bytes:
    return bytes(int(x, 16) for x in mac.split(":"))


def _make_dot11_deauth(
    src: str = "aa:bb:cc:dd:ee:ff",
    dst: str = "ff:ff:ff:ff:ff:ff",
    bssid: str = "11:22:33:44:55:66",
    reason: int = 7,
    subtype: int = DOT11_SUBTYPE_DEAUTH,
) -> bytes:
    """Build a minimal 802.11 deauth/disassoc frame (26 bytes)."""
    fc0 = (subtype << 4) | (0x00 << 2)  # type=management, subtype
    fc1 = 0x00
    fc = bytes([fc0, fc1])
    duration = b"\x00\x00"
    addr1 = _mac_bytes(dst)
    addr2 = _mac_bytes(src)
    addr3 = _mac_bytes(bssid)
    seq = b"\x00\x00"
    reason_bytes = struct.pack("<H", reason)
    return fc + duration + addr1 + addr2 + addr3 + seq + reason_bytes


def _make_radiotap_header(length: int = 8) -> bytes:
    """Build a minimal radiotap header of given length."""
    return struct.pack("<BBHI", 0, 0, length, 0) + b"\x00" * (length - 8)


def _make_pcap_global_header(network: int = LINKTYPE_IEEE80211) -> bytes:
    return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, network)


def _make_pcap_packet(payload: bytes, ts_sec: int = 1700000000, ts_usec: int = 0) -> bytes:
    return struct.pack("<IIII", ts_sec, ts_usec, len(payload), len(payload)) + payload


# ---------------------------------------------------------------------------
# _mac_from_bytes
# ---------------------------------------------------------------------------

class TestMacFromBytes:
    def test_broadcast(self) -> None:
        assert _mac_from_bytes(b"\xff\xff\xff\xff\xff\xff", 0) == "ff:ff:ff:ff:ff:ff"

    def test_specific_mac(self) -> None:
        assert _mac_from_bytes(b"\xaa\xbb\xcc\xdd\xee\xff", 0) == "aa:bb:cc:dd:ee:ff"


# ---------------------------------------------------------------------------
# parse_dot11_frame
# ---------------------------------------------------------------------------

class TestParseDot11Frame:
    def test_deauth_frame_parsed(self) -> None:
        raw = _make_dot11_deauth()
        frame = parse_dot11_frame(raw, timestamp=1000.0)
        assert frame is not None
        assert frame.frame_subtype == DOT11_SUBTYPE_DEAUTH
        assert frame.dst_mac == BROADCAST_MAC
        assert frame.reason_code == 7

    def test_disassoc_frame_parsed(self) -> None:
        raw = _make_dot11_deauth(subtype=DOT11_SUBTYPE_DISASSOC)
        frame = parse_dot11_frame(raw)
        assert frame is not None
        assert frame.frame_subtype == DOT11_SUBTYPE_DISASSOC

    def test_too_short_returns_none(self) -> None:
        assert parse_dot11_frame(b"\x00" * 10) is None

    def test_non_management_returns_none(self) -> None:
        # Set type bits to data (0x02 in bits 3:2)
        raw = bytearray(_make_dot11_deauth())
        raw[0] = (raw[0] & 0xF3) | (0x02 << 2)  # type = data
        assert parse_dot11_frame(bytes(raw)) is None


# ---------------------------------------------------------------------------
# strip_radiotap
# ---------------------------------------------------------------------------

class TestStripRadiotap:
    def test_strips_header(self) -> None:
        payload = _make_dot11_deauth()
        rt = _make_radiotap_header(8)
        remaining = strip_radiotap(rt + payload)
        assert remaining == payload

    def test_too_short_returns_none(self) -> None:
        assert strip_radiotap(b"\x00" * 4) is None

    def test_rt_len_exceeds_data_returns_none(self) -> None:
        bad = struct.pack("<BBHI", 0, 0, 9999, 0)
        assert strip_radiotap(bad) is None


# ---------------------------------------------------------------------------
# read_pcap_frames
# ---------------------------------------------------------------------------

class TestReadPcapFrames:
    def test_reads_single_frame(self) -> None:
        payload = _make_dot11_deauth()
        pcap = _make_pcap_global_header() + _make_pcap_packet(payload)
        frames = read_pcap_frames(pcap)
        assert len(frames) == 1

    def test_wrong_magic_empty(self) -> None:
        assert read_pcap_frames(b"\x00" * 100) == []

    def test_wrong_linktype_empty(self) -> None:
        pcap = _make_pcap_global_header(network=1) + _make_pcap_packet(b"\x00" * 20)
        assert read_pcap_frames(pcap) == []


# ---------------------------------------------------------------------------
# process_frame
# ---------------------------------------------------------------------------

class TestProcessFrame:
    def test_deauth_creates_event(self) -> None:
        state = DeauthDetectorState()
        raw = _make_dot11_deauth()
        event = process_frame(raw, 1000.0, LINKTYPE_IEEE80211, state)
        assert event is not None
        assert len(state.events) == 1

    def test_radiotap_frame_stripped(self) -> None:
        state = DeauthDetectorState()
        rt = _make_radiotap_header(8)
        raw = rt + _make_dot11_deauth()
        event = process_frame(raw, 1000.0, LINKTYPE_IEEE80211_RADIOTAP, state)
        assert event is not None

    def test_non_deauth_returns_none(self) -> None:
        state = DeauthDetectorState()
        # Beacon frame (subtype 8)
        data = bytearray(_make_dot11_deauth())
        data[0] = (8 << 4) | 0x00
        event = process_frame(bytes(data), 1000.0, LINKTYPE_IEEE80211, state)
        assert event is None
        assert not state.events


# ---------------------------------------------------------------------------
# analyse_events
# ---------------------------------------------------------------------------

class TestAnalyseEvents:
    def _make_events(self, count: int, src: str = "aa:bb:cc:dd:ee:ff",
                     bssid: str = "11:22:33:44:55:66") -> list[DeauthEvent]:
        return [
            DeauthEvent(
                timestamp=float(i),
                attacker_mac=src,
                victim_mac=BROADCAST_MAC,
                bssid=bssid,
                reason_code=7,
                is_broadcast=True,
                frame_subtype=DOT11_SUBTYPE_DEAUTH,
            )
            for i in range(count)
        ]

    def test_below_threshold_no_alarm(self) -> None:
        state = DeauthDetectorState(threshold=10)
        state.events = self._make_events(5)
        alarms = analyse_events(state)
        assert alarms == []

    def test_above_threshold_alarm(self) -> None:
        state = DeauthDetectorState(threshold=5)
        state.events = self._make_events(20)
        alarms = analyse_events(state)
        assert len(alarms) == 1
        assert alarms[0].count == 20

    def test_broadcast_ratio(self) -> None:
        state = DeauthDetectorState(threshold=5)
        state.events = self._make_events(10)  # all broadcast
        alarms = analyse_events(state)
        assert alarms[0].broadcast_ratio == 1.0
        assert alarms[0].severity == "high"

    def test_empty_events_no_alarm(self) -> None:
        state = DeauthDetectorState()
        alarms = analyse_events(state)
        assert alarms == []


# ---------------------------------------------------------------------------
# analyse_pcap (integration)
# ---------------------------------------------------------------------------

class TestAnalysePcap:
    def test_no_deauth_in_empty_pcap(self) -> None:
        state = analyse_pcap(b"\x00" * 10)
        assert not state.events

    def test_deauth_attack_detected(self) -> None:
        payload = _make_dot11_deauth()
        pkt = _make_pcap_packet(payload)
        pcap = _make_pcap_global_header() + pkt * 15
        state = analyse_pcap(pcap, threshold=10)
        assert len(state.events) == 15
        assert len(state.alarms) == 1
