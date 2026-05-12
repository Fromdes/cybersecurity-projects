"""Tests for project 70 ARP Spoofing Detector."""

from __future__ import annotations

import struct

import pytest

from project_70.core import (
    ARP_REPLY,
    ARP_REQUEST,
    ETHERTYPE_ARP,
    ARPConflict,
    ARPPacket,
    ARPTable,
    _ip_from_bytes,
    _mac_from_bytes,
    analyse_arp_log,
    analyse_pcap,
    parse_arp_packet,
    read_pcap_frames,
)


# ---------------------------------------------------------------------------
# Synthetic frame builders
# ---------------------------------------------------------------------------

def _mac_bytes(mac: str) -> bytes:
    return bytes(int(x, 16) for x in mac.split(":"))


def _ip_bytes(ip: str) -> bytes:
    return bytes(int(x) for x in ip.split("."))


def _make_arp_frame(
    sender_mac: str = "aa:bb:cc:dd:ee:01",
    sender_ip: str = "192.168.1.1",
    target_mac: str = "00:00:00:00:00:00",
    target_ip: str = "192.168.1.2",
    opcode: int = ARP_REPLY,
    eth_src: str | None = None,
    eth_dst: str = "ff:ff:ff:ff:ff:ff",
) -> bytes:
    if eth_src is None:
        eth_src = sender_mac
    eth = _mac_bytes(eth_dst) + _mac_bytes(eth_src) + struct.pack("!H", ETHERTYPE_ARP)
    arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, opcode)
    arp += _mac_bytes(sender_mac) + _ip_bytes(sender_ip)
    arp += _mac_bytes(target_mac) + _ip_bytes(target_ip)
    return eth + arp


def _make_pcap_global_header(network: int = 1) -> bytes:
    return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, network)


def _make_pcap_packet(payload: bytes, ts: int = 1700000000) -> bytes:
    return struct.pack("<IIII", ts, 0, len(payload), len(payload)) + payload


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class TestHelpers:
    def test_mac_from_bytes(self) -> None:
        assert _mac_from_bytes(b"\xaa\xbb\xcc\xdd\xee\xff", 0) == "aa:bb:cc:dd:ee:ff"

    def test_ip_from_bytes(self) -> None:
        assert _ip_from_bytes(b"\xc0\xa8\x01\x01", 0) == "192.168.1.1"


# ---------------------------------------------------------------------------
# ARPPacket
# ---------------------------------------------------------------------------

class TestARPPacket:
    def _pkt(self, sender_ip: str = "10.0.0.1", target_ip: str = "10.0.0.2",
              opcode: int = ARP_REPLY) -> ARPPacket:
        return ARPPacket(
            timestamp=0.0, opcode=opcode,
            sender_mac="aa:bb:cc:dd:ee:01", sender_ip=sender_ip,
            target_mac="00:00:00:00:00:00", target_ip=target_ip,
            eth_src="aa:bb:cc:dd:ee:01", eth_dst="ff:ff:ff:ff:ff:ff",
        )

    def test_gratuitous(self) -> None:
        p = self._pkt(sender_ip="10.0.0.1", target_ip="10.0.0.1")
        assert p.is_gratuitous

    def test_not_gratuitous(self) -> None:
        p = self._pkt(sender_ip="10.0.0.1", target_ip="10.0.0.2")
        assert not p.is_gratuitous

    def test_is_reply(self) -> None:
        p = self._pkt(opcode=ARP_REPLY)
        assert p.is_reply

    def test_is_not_reply(self) -> None:
        p = self._pkt(opcode=ARP_REQUEST)
        assert not p.is_reply


# ---------------------------------------------------------------------------
# parse_arp_packet
# ---------------------------------------------------------------------------

class TestParseArpPacket:
    def test_valid_arp_reply(self) -> None:
        raw = _make_arp_frame()
        pkt = parse_arp_packet(raw, timestamp=100.0)
        assert pkt is not None
        assert pkt.sender_ip == "192.168.1.1"
        assert pkt.opcode == ARP_REPLY
        assert pkt.timestamp == 100.0

    def test_too_short_returns_none(self) -> None:
        assert parse_arp_packet(b"\x00" * 10) is None

    def test_non_arp_returns_none(self) -> None:
        raw = bytearray(_make_arp_frame())
        # Change ethertype to IP
        struct.pack_into("!H", raw, 12, 0x0800)
        assert parse_arp_packet(bytes(raw)) is None

    def test_gratuitous_detected(self) -> None:
        raw = _make_arp_frame(sender_ip="192.168.1.5", target_ip="192.168.1.5")
        pkt = parse_arp_packet(raw)
        assert pkt is not None
        assert pkt.is_gratuitous


# ---------------------------------------------------------------------------
# ARPTable
# ---------------------------------------------------------------------------

class TestARPTable:
    def _pkt(self, ip: str, mac: str, opcode: int = ARP_REPLY, ts: float = 0.0) -> ARPPacket:
        return ARPPacket(
            timestamp=ts, opcode=opcode,
            sender_mac=mac, sender_ip=ip,
            target_mac="00:00:00:00:00:00", target_ip="0.0.0.0",
            eth_src=mac, eth_dst="ff:ff:ff:ff:ff:ff",
        )

    def test_first_entry_no_conflict(self) -> None:
        table = ARPTable()
        conflict = table.update(self._pkt("10.0.0.1", "aa:bb:cc:dd:ee:01"))
        assert conflict is None

    def test_same_mac_no_conflict(self) -> None:
        table = ARPTable()
        table.update(self._pkt("10.0.0.1", "aa:bb:cc:dd:ee:01"))
        conflict = table.update(self._pkt("10.0.0.1", "aa:bb:cc:dd:ee:01"))
        assert conflict is None

    def test_mac_change_conflict(self) -> None:
        table = ARPTable()
        table.update(self._pkt("10.0.0.1", "aa:bb:cc:dd:ee:01"))
        conflict = table.update(self._pkt("10.0.0.1", "ff:ff:ff:ff:ff:01"))
        assert conflict is not None
        assert conflict.old_mac == "aa:bb:cc:dd:ee:01"
        assert conflict.new_mac == "ff:ff:ff:ff:ff:01"

    def test_conflict_severity_critical_gratuitous(self) -> None:
        table = ARPTable()
        table.update(self._pkt("10.0.0.1", "aa:bb:cc:dd:ee:01"))
        grat_pkt = ARPPacket(
            timestamp=1.0, opcode=ARP_REPLY,
            sender_mac="ff:ff:ff:ff:ff:01", sender_ip="10.0.0.1",
            target_mac="00:00:00:00:00:00", target_ip="10.0.0.1",  # gratuitous
            eth_src="ff:ff:ff:ff:ff:01", eth_dst="ff:ff:ff:ff:ff:ff",
        )
        conflict = table.update(grat_pkt)
        assert conflict is not None
        assert conflict.severity == "critical"

    def test_get_mac(self) -> None:
        table = ARPTable()
        table.update(self._pkt("10.0.0.1", "aa:bb:cc:dd:ee:01"))
        assert table.get_mac("10.0.0.1") == "aa:bb:cc:dd:ee:01"

    def test_suspicious_macs(self) -> None:
        table = ARPTable()
        grat_pkt = ARPPacket(
            timestamp=0.0, opcode=ARP_REPLY,
            sender_mac="aa:bb:cc:dd:ee:ff", sender_ip="10.0.0.1",
            target_mac="00:00:00:00:00:00", target_ip="10.0.0.1",
            eth_src="aa:bb:cc:dd:ee:ff", eth_dst="ff:ff:ff:ff:ff:ff",
        )
        for _ in range(5):
            table.update(grat_pkt)
        assert "aa:bb:cc:dd:ee:ff" in table.suspicious_macs(threshold=3)


# ---------------------------------------------------------------------------
# read_pcap_frames
# ---------------------------------------------------------------------------

class TestReadPcapFrames:
    def test_reads_arp_frame(self) -> None:
        payload = _make_arp_frame()
        pcap = _make_pcap_global_header() + _make_pcap_packet(payload)
        frames = read_pcap_frames(pcap)
        assert len(frames) == 1

    def test_wrong_magic_empty(self) -> None:
        assert read_pcap_frames(b"\x00" * 100) == []

    def test_wrong_linktype_empty(self) -> None:
        pcap = _make_pcap_global_header(network=127) + _make_pcap_packet(b"\x00" * 42)
        assert read_pcap_frames(pcap) == []


# ---------------------------------------------------------------------------
# analyse_pcap / analyse_arp_log
# ---------------------------------------------------------------------------

class TestAnalysePcap:
    def test_conflict_detected(self) -> None:
        pkt1 = _make_arp_frame(sender_mac="aa:bb:cc:dd:ee:01", sender_ip="10.0.0.1")
        pkt2 = _make_arp_frame(sender_mac="ff:ff:ff:ff:ff:01", sender_ip="10.0.0.1")
        pcap = _make_pcap_global_header() + _make_pcap_packet(pkt1) + _make_pcap_packet(pkt2)
        table = analyse_pcap(pcap)
        assert len(table.conflicts) == 1

    def test_no_arp_no_conflict(self) -> None:
        table = analyse_pcap(b"\x00" * 10)
        assert not table.conflicts


class TestAnalyseArpLog:
    def test_conflict_from_neigh(self) -> None:
        lines = [
            "192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:01 REACHABLE",
            "192.168.1.1 dev eth0 lladdr ff:ff:ff:ff:ff:ff REACHABLE",
        ]
        table = analyse_arp_log(lines)
        assert len(table.conflicts) == 1

    def test_no_conflict_same_mac(self) -> None:
        lines = [
            "192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:01 REACHABLE",
            "192.168.1.2 dev eth0 lladdr bb:cc:dd:ee:ff:00 REACHABLE",
        ]
        table = analyse_arp_log(lines)
        assert not table.conflicts
