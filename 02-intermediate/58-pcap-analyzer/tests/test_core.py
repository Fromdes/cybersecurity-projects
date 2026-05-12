"""Tests for project 58 PCAP analyser (uses synthetic packet data)."""

from __future__ import annotations

import struct

import pytest

from project_58.core import (
    ETHERTYPE_IPV4,
    PROTOCOL_TCP,
    Packet,
    PCAPAnalyser,
    PCAPReader,
    _parse_packet,
)

# ---------------------------------------------------------------------------
# Helpers to build synthetic frames
# ---------------------------------------------------------------------------

def _make_eth_ip_tcp_frame(
    src_ip: str, dst_ip: str, src_port: int, dst_port: int,
    flags: int = 0x02, payload: bytes = b"hello",
) -> bytes:
    eth = b"\x00" * 12 + struct.pack("!H", ETHERTYPE_IPV4)
    ip_payload = struct.pack("!HH", src_port, dst_port) + b"\x00" * 12 + payload
    ihl = 5
    total_len = 20 + len(ip_payload)
    src = bytes(int(x) for x in src_ip.split("."))
    dst = bytes(int(x) for x in dst_ip.split("."))
    # data_offset=5<<4, flags=0x02 (SYN)
    ip = struct.pack("!BBHHHBBH", (4 << 4) | ihl, 0, total_len, 0, 0, 64,
                     PROTOCOL_TCP, 0) + src + dst
    # TCP: src_port, dst_port, seq, ack, offset+flags, window, chk, urg
    tcp = struct.pack("!HHIIBBHHH",
                      src_port, dst_port, 0, 0,
                      (5 << 4), flags, 65535, 0, 0)
    return eth + ip + tcp + payload


def _make_pcap_file(frames: list[bytes]) -> bytes:
    """Build a minimal PCAP file from a list of raw frames."""
    # Global header: magic, version_major, version_minor, thiszone, sigfigs, snaplen, link
    header = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    parts = [header]
    ts = 1700000000
    for frame in frames:
        pkt_hdr = struct.pack("<IIII", ts, 0, len(frame), len(frame))
        parts.append(pkt_hdr + frame)
        ts += 1
    return b"".join(parts)


class TestParsePacket:
    def test_tcp_packet(self) -> None:
        frame = _make_eth_ip_tcp_frame("10.0.0.1", "10.0.0.2", 1234, 80)
        pkt = _parse_packet(frame, 1000, 0)
        assert pkt is not None
        assert pkt.src_ip == "10.0.0.1"
        assert pkt.dst_ip == "10.0.0.2"
        assert pkt.src_port == 1234
        assert pkt.dst_port == 80
        assert pkt.protocol == PROTOCOL_TCP

    def test_non_ipv4_returns_none(self) -> None:
        # ARP frame: ethertype 0x0806
        frame = b"\x00" * 12 + struct.pack("!H", 0x0806) + b"\x00" * 50
        assert _parse_packet(frame, 0, 0) is None

    def test_too_short_returns_none(self) -> None:
        assert _parse_packet(b"\x00" * 10, 0, 0) is None


class TestPCAPReader:
    def test_reads_packets(self, tmp_path) -> None:
        frame = _make_eth_ip_tcp_frame("192.168.1.1", "8.8.8.8", 50000, 53)
        pcap_data = _make_pcap_file([frame, frame])
        f = tmp_path / "test.pcap"
        f.write_bytes(pcap_data)
        reader = PCAPReader(f)
        pkts = reader.packets()
        assert len(pkts) == 2

    def test_invalid_magic_raises(self, tmp_path) -> None:
        f = tmp_path / "bad.pcap"
        f.write_bytes(b"\x00" * 100)
        with pytest.raises(ValueError, match="PCAP"):
            PCAPReader(f)


class TestPCAPAnalyser:
    def _make_packets(self, count: int, src: str = "10.0.0.1", dst: str = "10.0.0.2",
                      dst_port: int = 80, flags: int = 0x02) -> list[Packet]:
        return [
            Packet(
                ts_sec=1700000000 + i, ts_usec=0,
                src_ip=src, dst_ip=dst,
                src_port=50000 + i, dst_port=dst_port,
                protocol=PROTOCOL_TCP, payload_len=100, tcp_flags=flags,
            )
            for i in range(count)
        ]

    def test_basic_stats(self) -> None:
        pkts = self._make_packets(10)
        stats = PCAPAnalyser().analyse(pkts)
        assert stats.total_packets == 10
        assert stats.total_bytes == 1000

    def test_empty_packets(self) -> None:
        stats = PCAPAnalyser().analyse([])
        assert stats.total_packets == 0

    def test_protocol_counts(self) -> None:
        pkts = self._make_packets(5)
        stats = PCAPAnalyser().analyse(pkts)
        assert stats.protocol_counts.get("tcp", 0) == 5

    def test_port_scan_detected(self) -> None:
        pkts = [
            Packet(
                ts_sec=1700000000, ts_usec=0,
                src_ip="10.0.0.99", dst_ip="10.0.0.1",
                src_port=1000, dst_port=port,
                protocol=PROTOCOL_TCP, payload_len=40, tcp_flags=0x02,
            )
            for port in range(1, 25)
        ]
        stats = PCAPAnalyser().analyse(pkts)
        assert any("PORT_SCAN" in a for a in stats.anomalies)

    def test_syn_flood_detected(self) -> None:
        pkts = [
            Packet(
                ts_sec=1700000000, ts_usec=0,
                src_ip="10.0.0.99", dst_ip="10.0.0.1",
                src_port=i, dst_port=80,
                protocol=PROTOCOL_TCP, payload_len=40, tcp_flags=0x02,
            )
            for i in range(55)
        ]
        stats = PCAPAnalyser().analyse(pkts)
        assert any("SYN_FLOOD" in a for a in stats.anomalies)

    def test_flow_aggregation(self) -> None:
        pkts = self._make_packets(3, dst_port=443)
        stats = PCAPAnalyser().analyse(pkts)
        assert len(stats.flows) >= 1
