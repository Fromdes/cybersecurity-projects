"""Tests for project 62 SSH brute-force detector."""

from __future__ import annotations

from project_62.core import (
    BruteForceDetector,
    LoginAttempt,
    analyse_auth_log,
    parse_line,
)

# Realistic auth.log lines
FAILED = "Jan  1 00:00:01 host sshd[1234]: Failed password for root from 10.0.0.1 port 22 ssh2"
FAILED2 = "Jan  1 00:00:02 host sshd[1234]: Failed password for admin from 10.0.0.1 port 22 ssh2"
INVALID = "Jan  1 00:00:03 host sshd[1234]: Invalid user ftp from 10.0.0.2 port 22"
ACCEPTED = "Jan  1 00:00:10 host sshd[1234]: Accepted password for alice from 10.0.0.3 port 22 ssh2"
NOISE = "Jan  1 00:00:00 host systemd[1]: Started session."


class TestParseLine:
    def test_failed_password(self) -> None:
        attempt = parse_line(FAILED, 1000.0)
        assert attempt is not None
        assert attempt.src_ip == "10.0.0.1"
        assert attempt.username == "root"
        assert attempt.success is False

    def test_invalid_user(self) -> None:
        attempt = parse_line(INVALID, 1000.0)
        assert attempt is not None
        assert attempt.src_ip == "10.0.0.2"
        assert attempt.success is False

    def test_accepted(self) -> None:
        attempt = parse_line(ACCEPTED, 1000.0)
        assert attempt is not None
        assert attempt.success is True

    def test_noise_returns_none(self) -> None:
        assert parse_line(NOISE) is None


class TestBruteForceDetector:
    def test_no_alert_below_threshold(self) -> None:
        det = BruteForceDetector(threshold=5, window=60)
        for i in range(4):
            det.record(LoginAttempt(
                timestamp=1000.0 + i, src_ip="10.0.0.1",
                username="root", success=False, raw_line="",
            ))
        alerts = det.analyse(current_time=1060.0)
        assert alerts == []

    def test_alert_above_threshold(self) -> None:
        det = BruteForceDetector(threshold=5, window=60)
        for i in range(8):
            det.record(LoginAttempt(
                timestamp=1000.0 + i, src_ip="10.0.0.1",
                username="root", success=False, raw_line="",
            ))
        alerts = det.analyse(current_time=1060.0)
        assert len(alerts) == 1
        assert alerts[0].src_ip == "10.0.0.1"

    def test_high_severity_triple_threshold(self) -> None:
        det = BruteForceDetector(threshold=5, window=600)
        for i in range(20):
            det.record(LoginAttempt(
                timestamp=1000.0 + i, src_ip="10.0.0.9",
                username="admin", success=False, raw_line="",
            ))
        alerts = det.analyse(current_time=1600.0)
        assert alerts[0].severity == "high"

    def test_attempts_outside_window_ignored(self) -> None:
        det = BruteForceDetector(threshold=3, window=10)
        for i in range(5):
            det.record(LoginAttempt(
                timestamp=1.0 + i, src_ip="10.0.0.1",
                username="root", success=False, raw_line="",
            ))
        alerts = det.analyse(current_time=1000.0)  # far future
        assert alerts == []

    def test_multiple_usernames_captured(self) -> None:
        det = BruteForceDetector(threshold=3, window=60)
        for user in ["root", "admin", "ubuntu", "pi"]:
            det.record(LoginAttempt(
                timestamp=1000.0, src_ip="10.0.0.1",
                username=user, success=False, raw_line="",
            ))
        alerts = det.analyse(current_time=1060.0)
        assert len(alerts[0].usernames) >= 3

    def test_reset_ip(self) -> None:
        det = BruteForceDetector(threshold=3, window=60)
        for i in range(5):
            det.record(LoginAttempt(
                timestamp=1000.0 + i, src_ip="10.0.0.1",
                username="root", success=False, raw_line="",
            ))
        det.reset_ip("10.0.0.1")
        alerts = det.analyse(current_time=1060.0)
        assert alerts == []


class TestAnalyseAuthLog:
    def _lines(self, ip: str, count: int) -> list[str]:
        return [
            f"Jan  1 00:{i // 60:02d}:{i % 60:02d} host sshd[1]: "
            f"Failed password for root from {ip} port 22 ssh2"
            for i in range(count)
        ]

    def test_detects_brute_force(self) -> None:
        lines = self._lines("10.0.0.5", 10)
        alerts = analyse_auth_log(lines, threshold=5, window=3600)
        assert len(alerts) == 1
        assert alerts[0].src_ip == "10.0.0.5"

    def test_clean_log(self) -> None:
        lines = self._lines("10.0.0.6", 3)
        alerts = analyse_auth_log(lines, threshold=5)
        assert alerts == []
