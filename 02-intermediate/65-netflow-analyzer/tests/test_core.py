"""Tests for project 65 NetFlow analyser."""

from __future__ import annotations

import struct

from project_65.core import (
    NetFlowRecord,
    _ip_from_uint32,
    analyse_records,
    parse_netflow_v5,
)

# ---------------------------------------------------------------------------
# Helpers to build synthetic NetFlow v5 data
# ---------------------------------------------------------------------------

def _ip_to_uint32(ip: str) -> int:
    parts = [int(x) for x in ip.split(".")]
    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]


def _make_v5_record(
    src: str = "10.0.0.1", dst: str = "10.0.0.2",
    sport: int = 12345, dport: int = 80,
    proto: int = 6, pkts: int = 10, octets: int = 1500,
    first: int = 1000, last: int = 2000,
    tcp_flags: int = 0x12, tos: int = 0,
) -> bytes:
    # 48 bytes: I I I H H I I I I H H B B B B H H B B xx (→ 48, trailing xx = 2-byte padding)
    return struct.pack(
        "!IIIHHIIIIHHBBBBHHBBxx",
        _ip_to_uint32(src), _ip_to_uint32(dst), 0,
        0, 0,
        pkts, octets, first, last,
        sport, dport,
        0, tcp_flags, proto, tos,
        0, 0, 0, 0,
    )


def _make_v5_packet(records: list[bytes]) -> bytes:
    count = len(records)
    header = struct.pack(
        "!HHIIIIBBH",
        5, count, 100000, 1700000000, 0, 42, 1, 1, 0,
    )
    return header + b"".join(records)


class TestIPFromUint32:
    def test_loopback(self) -> None:
        assert _ip_from_uint32(0x7F000001) == "127.0.0.1"

    def test_all_zeros(self) -> None:
        assert _ip_from_uint32(0) == "0.0.0.0"


class TestParseNetflowV5:
    def test_valid_packet(self) -> None:
        raw_rec = _make_v5_record()
        data = _make_v5_packet([raw_rec])
        packet = parse_netflow_v5(data)
        assert packet is not None
        assert packet.version == 5
        assert packet.count == 1
        assert len(packet.records) == 1

    def test_record_fields(self) -> None:
        raw_rec = _make_v5_record(src="192.168.1.1", dst="8.8.8.8", dport=443)
        data = _make_v5_packet([raw_rec])
        packet = parse_netflow_v5(data)
        assert packet is not None
        r = packet.records[0]
        assert r.src_ip == "192.168.1.1"
        assert r.dst_ip == "8.8.8.8"
        assert r.dst_port == 443

    def test_wrong_version_returns_none(self) -> None:
        data = struct.pack("!HH", 9, 0) + b"\x00" * 20
        assert parse_netflow_v5(data) is None

    def test_too_short_returns_none(self) -> None:
        assert parse_netflow_v5(b"\x00" * 10) is None

    def test_multiple_records(self) -> None:
        recs = [_make_v5_record(src=f"10.0.0.{i}") for i in range(5)]
        data = _make_v5_packet(recs)
        packet = parse_netflow_v5(data)
        assert packet is not None
        assert len(packet.records) == 5


class TestNetFlowRecord:
    def _rec(self, **kwargs) -> NetFlowRecord:
        defaults = {
            "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
            "src_port": 1234, "dst_port": 80, "protocol": 6,
            "packets": 5, "bytes_count": 500,
            "first_ms": 1000, "last_ms": 3000,
            "tcp_flags": 0x02, "tos": 0,
        }
        defaults.update(kwargs)
        return NetFlowRecord(**defaults)

    def test_protocol_name_tcp(self) -> None:
        assert self._rec().protocol_name == "tcp"

    def test_protocol_name_udp(self) -> None:
        assert self._rec(protocol=17).protocol_name == "udp"

    def test_duration(self) -> None:
        assert self._rec(first_ms=1000, last_ms=3000).duration_ms == 2000

    def test_tcp_flags(self) -> None:
        assert "SYN" in self._rec(tcp_flags=0x02).tcp_flag_names


class TestAnalyseRecords:
    def _make_records(self, n: int, src: str = "10.0.0.1") -> list[NetFlowRecord]:
        return [
            NetFlowRecord(
                src_ip=src, dst_ip=f"10.1.{i // 256}.{i % 256}",
                src_port=1000 + i, dst_port=80,
                protocol=6, packets=1, bytes_count=100,
                first_ms=0, last_ms=100, tcp_flags=0, tos=0,
            )
            for i in range(n)
        ]

    def test_empty(self) -> None:
        stats = analyse_records([])
        assert stats.total_flows == 0

    def test_basic_stats(self) -> None:
        recs = self._make_records(10)
        stats = analyse_records(recs)
        assert stats.total_flows == 10
        assert stats.total_bytes == 1000

    def test_scan_anomaly_detected(self) -> None:
        # 60 distinct destinations from same source
        recs = self._make_records(60)
        stats = analyse_records(recs)
        assert any("SCAN" in a for a in stats.anomalies)

    def test_large_flow_anomaly(self) -> None:
        recs = [NetFlowRecord(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=1, dst_port=443, protocol=6,
            packets=1000, bytes_count=200 * 1024 * 1024,
            first_ms=0, last_ms=1000, tcp_flags=0, tos=0,
        )]
        stats = analyse_records(recs)
        assert any("LARGE_FLOW" in a for a in stats.anomalies)

    def test_top_talkers(self) -> None:
        recs = self._make_records(5, src="10.0.0.99")
        stats = analyse_records(recs)
        top_ips = [ip for ip, _ in stats.top_talkers]
        assert "10.0.0.99" in top_ips
