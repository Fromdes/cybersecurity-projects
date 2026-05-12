"""Tests for project_31.core — Listening Port Auditor."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from project_31.core import (
    DANGEROUS_PORTS,
    RISK_HIGH,
    RISK_MEDIUM,
    PortEntry,
    _compute_risk,
    _score_to_level,
    filter_by_risk,
    list_listening_ports,
)


def _make_conn(
    ip: str = "127.0.0.1",
    port: int = 8080,
    pid: int | None = 1234,
    status: str = "LISTEN",
) -> MagicMock:
    conn = MagicMock()
    conn.laddr = MagicMock(ip=ip, port=port)
    conn.pid = pid
    conn.status = status
    return conn


class TestComputeRisk:
    def test_world_bind_raises_score(self) -> None:
        score, flags = _compute_risk(8080, "0.0.0.0", 1234, "tcp")
        assert score >= 30
        assert any("all interfaces" in f for f in flags)

    def test_dangerous_port_raises_score(self) -> None:
        port = next(iter(DANGEROUS_PORTS))
        score, _flags = _compute_risk(port, "127.0.0.1", 1234, "tcp")
        assert score >= 50

    def test_telnet_port_extra_score(self) -> None:
        score, flags = _compute_risk(23, "127.0.0.1", 1234, "tcp")
        assert score >= 100
        assert any("telnet" in f.lower() for f in flags)

    def test_no_pid_raises_score(self) -> None:
        score, flags = _compute_risk(8080, "127.0.0.1", None, "tcp")
        assert score >= 40
        assert any("no owning process" in f for f in flags)

    def test_safe_port_low_score(self) -> None:
        score, _ = _compute_risk(8080, "127.0.0.1", 1234, "tcp")
        assert score < RISK_HIGH

    def test_ephemeral_port_server_flagged(self) -> None:
        score, flags = _compute_risk(50000, "127.0.0.1", 1234, "tcp")
        assert score >= 20
        assert any("ephemeral" in f for f in flags)


class TestScoreToLevel:
    def test_high(self) -> None:
        assert _score_to_level(RISK_HIGH) == "HIGH"

    def test_medium(self) -> None:
        assert _score_to_level(RISK_MEDIUM) == "MEDIUM"

    def test_low(self) -> None:
        assert _score_to_level(0) == "LOW"


class TestFilterByRisk:
    def _make_entry(self, score: int, level: str) -> PortEntry:
        return PortEntry(
            port=80, protocol="tcp", local_address="127.0.0.1",
            pid=1, process_name="nginx", username="www-data",
            service_guess="http", risk_score=score,
            risk_level=level, risk_flags=(),
        )

    def test_filter_medium_excludes_low(self) -> None:
        entries = [
            self._make_entry(0, "LOW"),
            self._make_entry(RISK_MEDIUM, "MEDIUM"),
            self._make_entry(RISK_HIGH, "HIGH"),
        ]
        result = filter_by_risk(entries, "MEDIUM")
        assert all(e.risk_score >= RISK_MEDIUM for e in result)

    def test_filter_high_only(self) -> None:
        entries = [
            self._make_entry(0, "LOW"),
            self._make_entry(RISK_MEDIUM, "MEDIUM"),
            self._make_entry(RISK_HIGH, "HIGH"),
        ]
        result = filter_by_risk(entries, "HIGH")
        assert len(result) == 1
        assert result[0].risk_level == "HIGH"

    def test_filter_low_returns_all(self) -> None:
        entries = [
            self._make_entry(0, "LOW"),
            self._make_entry(RISK_HIGH, "HIGH"),
        ]
        result = filter_by_risk(entries, "LOW")
        assert len(result) == 2

    def test_invalid_level_raises(self) -> None:
        with pytest.raises(ValueError, match="min_level"):
            filter_by_risk([], "CRITICAL")


class TestListListeningPorts:
    @patch("project_31.core.psutil.net_connections")
    @patch("project_31.core.psutil.Process")
    def test_returns_list(self, mock_proc: MagicMock, mock_net: MagicMock) -> None:
        conn = _make_conn(port=22, status="LISTEN")
        mock_net.return_value = [conn]
        mock_proc.return_value.name.return_value = "sshd"
        mock_proc.return_value.username.return_value = "root"
        result = list_listening_ports("tcp")
        assert isinstance(result, list)

    @patch("project_31.core.psutil.net_connections")
    def test_skips_non_listen_tcp(self, mock_net: MagicMock) -> None:
        conn = _make_conn(port=22, status="ESTABLISHED")
        mock_net.return_value = [conn]
        result = list_listening_ports("tcp")
        assert result == []

    def test_invalid_protocol_raises(self) -> None:
        with pytest.raises(ValueError, match="protocol"):
            list_listening_ports("ftp")

    @patch("project_31.core.psutil.net_connections")
    def test_deduplicates_entries(self, mock_net: MagicMock) -> None:
        conn = _make_conn(port=80, status="LISTEN")
        mock_net.return_value = [conn, conn]
        result = list_listening_ports("tcp")
        ports = [e.port for e in result]
        assert ports.count(80) == 1
