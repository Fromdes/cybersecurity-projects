"""Parse Nmap XML output and diff two scan results."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PortInfo:
    """A single open port entry from an Nmap scan."""

    port: int
    protocol: str
    state: str
    service: str
    product: str
    version: str
    extra_info: str


@dataclass
class HostResult:
    """Parsed result for a single scanned host."""

    address: str
    hostname: str
    status: str   # "up" | "down"
    ports: list[PortInfo] = field(default_factory=list)
    os_guesses: list[str] = field(default_factory=list)

    def open_ports(self) -> list[PortInfo]:
        return [p for p in self.ports if p.state == "open"]


@dataclass
class ScanResult:
    """Full parsed Nmap XML scan result."""

    scanner: str
    args: str
    start_time: str
    hosts: dict[str, HostResult] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def parse_nmap_xml(xml_content: str) -> ScanResult:
    """Parse Nmap XML output into a ScanResult."""
    root = ET.fromstring(xml_content)

    result = ScanResult(
        scanner=root.get("scanner", "nmap"),
        args=root.get("args", ""),
        start_time=root.get("startstr", ""),
    )

    for host_el in root.iter("host"):
        host = _parse_host(host_el)
        result.hosts[host.address] = host

    return result


def _parse_host(host_el: ET.Element) -> HostResult:
    """Parse a single <host> element."""
    address = ""
    hostname = ""
    status = "down"

    for addr_el in host_el.findall("address"):
        if addr_el.get("addrtype") in {"ipv4", "ipv6"}:
            address = addr_el.get("addr", "")

    hostnames_el = host_el.find("hostnames")
    if hostnames_el is not None:
        first = hostnames_el.find("hostname")
        if first is not None:
            hostname = first.get("name", "")

    status_el = host_el.find("status")
    if status_el is not None:
        status = status_el.get("state", "down")

    ports: list[PortInfo] = []
    ports_el = host_el.find("ports")
    if ports_el is not None:
        for port_el in ports_el.findall("port"):
            ports.append(_parse_port(port_el))

    os_guesses: list[str] = []
    os_el = host_el.find("os")
    if os_el is not None:
        for match_el in os_el.findall("osmatch"):
            name = match_el.get("name", "")
            accuracy = match_el.get("accuracy", "?")
            os_guesses.append(f"{name} ({accuracy}%)")

    return HostResult(
        address=address,
        hostname=hostname,
        status=status,
        ports=ports,
        os_guesses=os_guesses,
    )


def _parse_port(port_el: ET.Element) -> PortInfo:
    """Parse a single <port> element."""
    state_el = port_el.find("state")
    state = state_el.get("state", "unknown") if state_el is not None else "unknown"

    svc_el = port_el.find("service")
    if svc_el is not None:
        service = svc_el.get("name", "")
        product = svc_el.get("product", "")
        version = svc_el.get("version", "")
        extra_info = svc_el.get("extrainfo", "")
    else:
        service = product = version = extra_info = ""

    return PortInfo(
        port=int(port_el.get("portid", "0")),
        protocol=port_el.get("protocol", "tcp"),
        state=state,
        service=service,
        product=product,
        version=version,
        extra_info=extra_info,
    )


# ---------------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------------

@dataclass
class PortDiff:
    """Change in port state between two scans."""

    address: str
    port: int
    protocol: str
    change: str  # "opened" | "closed" | "service_changed"
    before: PortInfo | None = None
    after: PortInfo | None = None


@dataclass
class ScanDiff:
    """Differences between two scans."""

    new_hosts: list[str] = field(default_factory=list)
    removed_hosts: list[str] = field(default_factory=list)
    port_changes: list[PortDiff] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(self.new_hosts or self.removed_hosts or self.port_changes)


def diff_scans(baseline: ScanResult, current: ScanResult) -> ScanDiff:
    """Compare two scan results and return the differences."""
    diff = ScanDiff()

    baseline_addrs = set(baseline.hosts)
    current_addrs = set(current.hosts)

    diff.new_hosts = sorted(current_addrs - baseline_addrs)
    diff.removed_hosts = sorted(baseline_addrs - current_addrs)

    for addr in baseline_addrs & current_addrs:
        baseline_host = baseline.hosts[addr]
        current_host = current.hosts[addr]

        baseline_ports = {(p.port, p.protocol): p for p in baseline_host.ports}
        current_ports = {(p.port, p.protocol): p for p in current_host.ports}

        for key, port in current_ports.items():
            if key not in baseline_ports:
                diff.port_changes.append(PortDiff(
                    address=addr, port=port.port, protocol=port.protocol,
                    change="opened", after=port,
                ))
            else:
                old_port = baseline_ports[key]
                if old_port.state != port.state and port.state == "open":
                    diff.port_changes.append(PortDiff(
                        address=addr, port=port.port, protocol=port.protocol,
                        change="opened", before=old_port, after=port,
                    ))
                elif old_port.service != port.service or old_port.version != port.version:
                    diff.port_changes.append(PortDiff(
                        address=addr, port=port.port, protocol=port.protocol,
                        change="service_changed", before=old_port, after=port,
                    ))

        for key, port in baseline_ports.items():
            if key not in current_ports:
                diff.port_changes.append(PortDiff(
                    address=addr, port=port.port, protocol=port.protocol,
                    change="closed", before=port,
                ))

    return diff
