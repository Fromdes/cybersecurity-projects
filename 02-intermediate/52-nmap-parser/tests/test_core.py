"""Tests for project 52 Nmap parser and diff."""

from __future__ import annotations

import pytest

from project_52.core import PortInfo, diff_scans, parse_nmap_xml

SIMPLE_XML = """\
<?xml version="1.0"?>
<nmaprun scanner="nmap" args="-sV 192.168.1.1" startstr="2024-01-01">
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <hostnames><hostname name="router.local" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.9" extrainfo="protocol 2.0"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="nginx" version="1.24"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

UPDATED_XML = """\
<?xml version="1.0"?>
<nmaprun scanner="nmap" args="-sV 192.168.1.1" startstr="2024-01-02">
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <hostnames><hostname name="router.local" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="9.0" extrainfo="protocol 2.0"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" product="nginx" version="1.24"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="192.168.1.2" addrtype="ipv4"/>
    <hostnames/>
    <ports/>
  </host>
</nmaprun>
"""


class TestParseNmapXml:
    def test_basic_parse(self) -> None:
        result = parse_nmap_xml(SIMPLE_XML)
        assert "192.168.1.1" in result.hosts

    def test_host_status(self) -> None:
        result = parse_nmap_xml(SIMPLE_XML)
        assert result.hosts["192.168.1.1"].status == "up"

    def test_hostname(self) -> None:
        result = parse_nmap_xml(SIMPLE_XML)
        assert result.hosts["192.168.1.1"].hostname == "router.local"

    def test_port_count(self) -> None:
        result = parse_nmap_xml(SIMPLE_XML)
        assert len(result.hosts["192.168.1.1"].ports) == 2

    def test_port_details(self) -> None:
        result = parse_nmap_xml(SIMPLE_XML)
        ports = {p.port: p for p in result.hosts["192.168.1.1"].ports}
        assert ports[22].service == "ssh"
        assert ports[22].product == "OpenSSH"
        assert ports[22].version == "8.9"

    def test_open_ports_filter(self) -> None:
        result = parse_nmap_xml(SIMPLE_XML)
        open_ports = result.hosts["192.168.1.1"].open_ports()
        assert all(p.state == "open" for p in open_ports)


class TestDiffScans:
    def test_new_host_detected(self) -> None:
        baseline = parse_nmap_xml(SIMPLE_XML)
        current = parse_nmap_xml(UPDATED_XML)
        diff = diff_scans(baseline, current)
        assert "192.168.1.2" in diff.new_hosts

    def test_closed_port_detected(self) -> None:
        baseline = parse_nmap_xml(SIMPLE_XML)
        current = parse_nmap_xml(UPDATED_XML)
        diff = diff_scans(baseline, current)
        closed = [c for c in diff.port_changes if c.change == "closed"]
        assert any(c.port == 80 for c in closed)

    def test_new_port_detected(self) -> None:
        baseline = parse_nmap_xml(SIMPLE_XML)
        current = parse_nmap_xml(UPDATED_XML)
        diff = diff_scans(baseline, current)
        opened = [c for c in diff.port_changes if c.change == "opened"]
        assert any(c.port == 443 for c in opened)

    def test_service_changed(self) -> None:
        baseline = parse_nmap_xml(SIMPLE_XML)
        current = parse_nmap_xml(UPDATED_XML)
        diff = diff_scans(baseline, current)
        changed = [c for c in diff.port_changes if c.change == "service_changed"]
        assert any(c.port == 22 for c in changed)

    def test_no_changes_when_identical(self) -> None:
        result = parse_nmap_xml(SIMPLE_XML)
        diff = diff_scans(result, result)
        assert not diff.has_changes
