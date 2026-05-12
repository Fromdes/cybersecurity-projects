"""Tests for project 53 port scan detector."""

from __future__ import annotations

import pytest

from project_53.core import (
    ScanDetector,
    analyse_log_file,
    parse_connection_line,
)


class TestParseConnectionLine:
    def test_iptables_line(self) -> None:
        line = "Jan  1 00:00:01 host kernel: [UFW BLOCK] SRC=10.0.0.1 DST=192.168.1.1 DPT=22"
        result = parse_connection_line(line)
        assert result == ("10.0.0.1", 22)

    def test_returns_none_for_unknown(self) -> None:
        result = parse_connection_line("some random log line with no ip or port")
        assert result is None

    def test_multi_digit_port(self) -> None:
        line = "SRC=1.2.3.4 DST=5.6.7.8 DPT=8080"
        result = parse_connection_line(line)
        assert result == ("1.2.3.4", 8080)


class TestScanDetector:
    def test_no_alert_below_threshold(self) -> None:
        det = ScanDetector(port_threshold=15, window_seconds=60.0)
        for port in range(1, 10):
            det.record("10.0.0.1", port, 100.0 + port)
        alerts = det.analyse(160.0)
        assert alerts == []

    def test_alert_above_threshold(self) -> None:
        det = ScanDetector(port_threshold=15, window_seconds=60.0)
        for port in range(1, 20):
            det.record("10.0.0.1", port, 100.0 + port * 0.1)
        alerts = det.analyse(110.0)
        assert len(alerts) == 1
        assert alerts[0].source_ip == "10.0.0.1"

    def test_events_outside_window_ignored(self) -> None:
        det = ScanDetector(port_threshold=5, window_seconds=10.0)
        for port in range(1, 10):
            det.record("10.0.0.1", port, 1.0)  # old events
        alerts = det.analyse(200.0)  # far future
        assert alerts == []

    def test_severity_high_100_ports(self) -> None:
        det = ScanDetector(port_threshold=5, window_seconds=3600.0)
        for port in range(1, 110):
            det.record("10.0.0.2", port, 1000.0 + port)
        alerts = det.analyse(2000.0)
        assert alerts[0].severity == "high"

    def test_scan_type_horizontal(self) -> None:
        det = ScanDetector(port_threshold=5, window_seconds=3600.0)
        for port in range(22, 40):
            det.record("10.0.0.3", port, 1000.0 + port)
        alerts = det.analyse(2000.0)
        assert alerts[0].scan_type == "horizontal"

    def test_reset_clears_ip(self) -> None:
        det = ScanDetector(port_threshold=5, window_seconds=60.0)
        for port in range(1, 10):
            det.record("10.0.0.1", port, 1.0)
        det.reset("10.0.0.1")
        alerts = det.analyse(60.0)
        assert alerts == []


class TestAnalyseLogFile:
    def _make_lines(self, src: str, ports: list[int]) -> list[str]:
        return [f"SRC={src} DST=192.168.1.1 DPT={p}" for p in ports]

    def test_detects_scan(self) -> None:
        lines = self._make_lines("10.0.0.99", list(range(1, 30)))
        alerts = analyse_log_file(lines, port_threshold=15)
        assert len(alerts) == 1
        assert alerts[0].source_ip == "10.0.0.99"

    def test_no_scan_below_threshold(self) -> None:
        lines = self._make_lines("10.0.0.99", list(range(1, 5)))
        alerts = analyse_log_file(lines, port_threshold=15)
        assert alerts == []

    def test_multiple_sources(self) -> None:
        lines = (
            self._make_lines("10.0.0.1", list(range(1, 25)))
            + self._make_lines("10.0.0.2", list(range(1, 25)))
        )
        alerts = analyse_log_file(lines, port_threshold=15)
        src_ips = {a.source_ip for a in alerts}
        assert "10.0.0.1" in src_ips
        assert "10.0.0.2" in src_ips
