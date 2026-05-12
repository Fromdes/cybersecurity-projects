"""Tests for project 71 Rogue DHCP Detector."""

from __future__ import annotations

import struct

import pytest

from project_71.core import (
    DHCP_ACK,
    DHCP_MAGIC_COOKIE,
    DHCP_OFFER,
    DHCP_REQUEST,
    DHCP_SERVER_PORT,
    DHCP_CLIENT_PORT,
    ETHERTYPE_IP,
    OPT_DNS,
    OPT_END,
    OPT_MESSAGE_TYPE,
    OPT_ROUTER,
    OPT_SERVER_ID,
    OPT_SUBNET,
    PROTO_UDP,
    DHCPMonitorState,
    DHCPPacket,
    _ip_from_bytes,
    _mac_from_bytes,
    analyse_pcap,
    parse_dhcp_options,
    parse_dhcp_packet,
    process_packet,
    read_pcap_frames,
)


# ---------------------------------------------------------------------------
# Synthetic frame builder
# ---------------------------------------------------------------------------

def _ip_bytes(ip: str) -> bytes:
    return bytes(int(x) for x in ip.split("."))


def _mac_bytes(mac: str) -> bytes:
    return bytes(int(x, 16) for x in mac.split(":"))


def _dhcp_options(
    msg_type: int,
    server_id: str = "192.168.1.1",
    router: str = "192.168.1.1",
    subnet: str = "255.255.255.0",
) -> bytes:
    opts = bytes([OPT_MESSAGE_TYPE, 1, msg_type])
    opts += bytes([OPT_SERVER_ID, 4]) + _ip_bytes(server_id)
    opts += bytes([OPT_ROUTER, 4]) + _ip_bytes(router)
    opts += bytes([OPT_SUBNET, 4]) + _ip_bytes(subnet)
    opts += bytes([OPT_END])
    return opts


def _make_bootp(
    yiaddr: str = "192.168.1.100",
    msg_type: int = DHCP_OFFER,
    server_id: str = "192.168.1.1",
) -> bytes:
    # op(1) htype(1) hlen(1) hops(1) xid(4) secs(2) flags(2)
    # ciaddr(4) yiaddr(4) siaddr(4) giaddr(4) chaddr(16) sname(64) file(128)
    fixed = struct.pack("!BBBBI HH", 2, 1, 6, 0, 12345678, 0, 0)
    fixed += b"\x00" * 4  # ciaddr
    fixed += _ip_bytes(yiaddr)  # yiaddr
    fixed += b"\x00" * 4  # siaddr
    fixed += b"\x00" * 4  # giaddr
    fixed += b"\xaa\xbb\xcc\xdd\xee\x01" + b"\x00" * 10  # chaddr (16 bytes)
    fixed += b"\x00" * 64  # sname
    fixed += b"\x00" * 128  # file
    assert len(fixed) == 236, f"BOOTP fixed size error: {len(fixed)}"
    opts = _dhcp_options(msg_type, server_id)
    return fixed + DHCP_MAGIC_COOKIE + opts


def _make_udp_dhcp(
    src_ip: str = "192.168.1.1",
    eth_src: str = "aa:bb:cc:dd:ee:01",
    msg_type: int = DHCP_OFFER,
    server_id: str | None = None,
) -> bytes:
    bootp = _make_bootp(msg_type=msg_type, server_id=server_id or src_ip)

    udp_len = 8 + len(bootp)
    udp = struct.pack("!HHH", DHCP_SERVER_PORT, DHCP_CLIENT_PORT, udp_len) + b"\x00\x00"
    udp += bootp

    ip_total_len = 20 + len(udp)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, ip_total_len, 0, 0, 64, PROTO_UDP, 0,
        _ip_bytes(src_ip), b"\xff\xff\xff\xff",
    )

    eth = _mac_bytes("ff:ff:ff:ff:ff:ff") + _mac_bytes(eth_src) + struct.pack("!H", ETHERTYPE_IP)
    return eth + ip + udp


def _make_pcap_global_header(network: int = 1) -> bytes:
    return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, network)


def _make_pcap_packet(payload: bytes, ts: int = 1700000000) -> bytes:
    return struct.pack("<IIII", ts, 0, len(payload), len(payload)) + payload


# ---------------------------------------------------------------------------
# Unit tests
# ---------------------------------------------------------------------------

class TestHelpers:
    def test_ip_from_bytes(self) -> None:
        assert _ip_from_bytes(b"\xc0\xa8\x01\x01") == "192.168.1.1"

    def test_mac_from_bytes(self) -> None:
        assert _mac_from_bytes(b"\xaa\xbb\xcc\xdd\xee\xff") == "aa:bb:cc:dd:ee:ff"


class TestParseDhcpOptions:
    def test_message_type(self) -> None:
        opts = bytes([OPT_MESSAGE_TYPE, 1, DHCP_OFFER, OPT_END])
        parsed = parse_dhcp_options(opts)
        assert parsed[OPT_MESSAGE_TYPE] == bytes([DHCP_OFFER])

    def test_pad_ignored(self) -> None:
        opts = bytes([0, OPT_MESSAGE_TYPE, 1, DHCP_OFFER, OPT_END])
        parsed = parse_dhcp_options(opts)
        assert OPT_MESSAGE_TYPE in parsed

    def test_end_stops_parse(self) -> None:
        opts = bytes([OPT_END, OPT_MESSAGE_TYPE, 1, DHCP_OFFER])
        parsed = parse_dhcp_options(opts)
        assert OPT_MESSAGE_TYPE not in parsed

    def test_dns_servers(self) -> None:
        opts = bytes([OPT_DNS, 8]) + _ip_bytes("8.8.8.8") + _ip_bytes("8.8.4.4") + bytes([OPT_END])
        parsed = parse_dhcp_options(opts)
        assert len(parsed[OPT_DNS]) == 8


class TestParseDhcpPacket:
    def test_dhcp_offer_parsed(self) -> None:
        raw = _make_udp_dhcp()
        pkt = parse_dhcp_packet(raw, timestamp=1000.0)
        assert pkt is not None
        assert pkt.is_offer
        assert pkt.server_id == "192.168.1.1"
        assert pkt.timestamp == 1000.0

    def test_too_short_returns_none(self) -> None:
        assert parse_dhcp_packet(b"\x00" * 10) is None

    def test_non_dhcp_port_returns_none(self) -> None:
        raw = bytearray(_make_udp_dhcp())
        # Change src port to non-DHCP
        struct.pack_into("!H", raw, 14 + 20, 12345)
        assert parse_dhcp_packet(bytes(raw)) is None

    def test_dhcp_request_returns_none(self) -> None:
        # DHCP REQUEST from client (src_port=68, dst_port=67) — not an offer
        raw = _make_udp_dhcp(msg_type=DHCP_REQUEST)
        assert parse_dhcp_packet(raw) is None

    def test_dhcp_ack(self) -> None:
        raw = _make_udp_dhcp(msg_type=DHCP_ACK)
        pkt = parse_dhcp_packet(raw)
        assert pkt is not None
        assert pkt.is_ack


class TestDHCPMonitorState:
    def _offer_pkt(self, server_ip: str = "192.168.1.1", mac: str = "aa:bb:cc:dd:ee:01") -> DHCPPacket:
        return DHCPPacket(
            timestamp=0.0, src_mac=mac, src_ip=server_ip, server_id=server_ip,
            message_type=DHCP_OFFER, offered_ip="192.168.1.100",
            router="192.168.1.1", dns_servers=[], lease_time=86400,
            subnet_mask="255.255.255.0",
        )

    def test_authorised_server_no_alert(self) -> None:
        state = DHCPMonitorState(authorised_servers=frozenset({"192.168.1.1"}))
        alert = process_packet(self._offer_pkt("192.168.1.1"), state)
        assert alert is None

    def test_rogue_server_alert(self) -> None:
        state = DHCPMonitorState(authorised_servers=frozenset({"192.168.1.1"}))
        alert = process_packet(self._offer_pkt("10.0.0.99"), state)
        assert alert is not None
        assert alert.server_ip == "10.0.0.99"
        assert alert.severity == "critical"

    def test_alert_appended_to_state(self) -> None:
        state = DHCPMonitorState(authorised_servers=frozenset())
        process_packet(self._offer_pkt(), state)
        assert len(state.alerts) == 1

    def test_packet_appended_to_state(self) -> None:
        state = DHCPMonitorState(authorised_servers=frozenset({"192.168.1.1"}))
        process_packet(self._offer_pkt(), state)
        assert len(state.packets) == 1


class TestAnalysePcap:
    def test_rogue_server_detected(self) -> None:
        raw = _make_udp_dhcp(src_ip="10.99.99.99", eth_src="de:ad:be:ef:00:01",
                             server_id="10.99.99.99")
        pcap = _make_pcap_global_header() + _make_pcap_packet(raw)
        state = analyse_pcap(pcap, authorised_servers=["192.168.1.1"])
        assert len(state.alerts) == 1

    def test_authorised_no_alert(self) -> None:
        raw = _make_udp_dhcp(src_ip="192.168.1.1")
        pcap = _make_pcap_global_header() + _make_pcap_packet(raw)
        state = analyse_pcap(pcap, authorised_servers=["192.168.1.1"])
        assert not state.alerts

    def test_empty_pcap_no_alerts(self) -> None:
        state = analyse_pcap(b"\x00" * 10, authorised_servers=["192.168.1.1"])
        assert not state.alerts
