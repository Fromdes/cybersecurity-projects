"""Tests for Mini SIEM Platform core."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path

from project_76.core import (
    BUILTIN_RULES,
    Alert,
    AlertStore,
    ApacheParser,
    DetectionRule,
    LogEvent,
    Severity,
    SIEMEngine,
    SyslogParser,
    get_parser,
)


def make_event(message: str, source: str = "test") -> LogEvent:
    ts = datetime.now(UTC)
    return LogEvent(
        event_id=LogEvent._make_id(message, ts),
        timestamp=ts,
        source=source,
        message=message,
        raw=message,
    )


class TestDetectionRule:
    def test_matches_true(self) -> None:
        rule = DetectionRule(
            name="TEST",
            pattern=re.compile(r"failed password", re.IGNORECASE),
            severity=Severity.HIGH,
            description="test",
        )
        assert rule.matches(make_event("Failed password for root"))

    def test_matches_false(self) -> None:
        rule = DetectionRule(
            name="TEST",
            pattern=re.compile(r"failed password", re.IGNORECASE),
            severity=Severity.HIGH,
            description="test",
        )
        assert not rule.matches(make_event("Accepted password for user"))


class TestSyslogParser:
    def test_parse_valid_line(self) -> None:
        parser = SyslogParser()
        line = "May 12 10:00:01 myhost sshd[1234]: Failed password for root from 1.2.3.4 port 22"
        event = parser.parse_line(line)
        assert event is not None
        assert "Failed password" in event.message

    def test_parse_empty(self) -> None:
        parser = SyslogParser()
        assert parser.parse_line("") is None
        assert parser.parse_line("   ") is None

    def test_parse_generic_fallback(self) -> None:
        parser = SyslogParser()
        event = parser.parse_line("some random line without syslog format")
        assert event is not None
        assert event.source == "syslog"


class TestApacheParser:
    def test_parse_access_log(self) -> None:
        parser = ApacheParser()
        line = '192.168.1.1 - - [10/May/2024:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234'
        event = parser.parse_line(line)
        assert event is not None
        assert "192.168.1.1" in event.message

    def test_parse_empty(self) -> None:
        parser = ApacheParser()
        assert parser.parse_line("") is None


class TestAlertStore:
    def test_add_and_get(self) -> None:
        store = AlertStore()
        event = make_event("test message")
        alert = Alert(
            alert_id="abc123",
            rule_name="TEST",
            severity=Severity.HIGH,
            message="test alert",
            event=event,
        )
        store.add(alert)
        alerts = store.get_all()
        assert len(alerts) == 1
        assert alerts[0].rule_name == "TEST"

    def test_count_by_severity(self) -> None:
        store = AlertStore()
        event = make_event("test")
        for sev in [Severity.LOW, Severity.HIGH, Severity.HIGH]:
            a = Alert(alert_id=f"id-{sev.value}", rule_name="R", severity=sev, message="m", event=event)
            store.add(a)
        counts = store.count_by_severity()
        assert counts["HIGH"] == 2
        assert counts["LOW"] == 1
        assert counts["CRITICAL"] == 0

    def test_write_to_file(self, tmp_path: Path) -> None:
        out = tmp_path / "alerts.jsonl"
        store = AlertStore(output_path=out)
        event = make_event("test")
        alert = Alert(alert_id="x", rule_name="R", severity=Severity.MEDIUM, message="m", event=event)
        store.add(alert)
        assert out.exists()
        lines = out.read_text().strip().split("\n")
        assert len(lines) == 1
        import json
        obj = json.loads(lines[0])
        assert obj["rule_name"] == "R"


class TestSIEMEngine:
    def test_ssh_brute_force_fires(self) -> None:
        engine = SIEMEngine()
        event = make_event("Failed password for root from 10.0.0.1 port 22 ssh2")
        alerts = engine.process_event(event)
        rule_names = [a.rule_name for a in alerts]
        assert "SSH_BRUTE_FORCE" in rule_names

    def test_no_alert_on_benign(self) -> None:
        engine = SIEMEngine()
        event = make_event("System startup complete")
        assert engine.process_event(event) == []

    def test_root_login_fires(self) -> None:
        engine = SIEMEngine()
        event = make_event("pam_unix(sshd:session): session opened for user root by (uid=0)")
        alerts = engine.process_event(event)
        assert any(a.rule_name == "ROOT_LOGIN" for a in alerts)

    def test_ingest_file(self, tmp_path: Path) -> None:
        log = tmp_path / "test.log"
        log.write_text(
            "May 12 10:00:01 host sshd[1]: Failed password for user from 1.2.3.4 port 22\n"
            "May 12 10:00:02 host sudo: user : COMMAND=/bin/bash\n"
            "May 12 10:00:03 host kernel: normal log line\n"
        )
        engine = SIEMEngine()
        parser = get_parser("syslog")
        lines, alert_count = engine.ingest_file(log, parser)
        assert lines == 3
        assert alert_count >= 2

    def test_callback_invoked(self) -> None:
        received: list[Alert] = []
        engine = SIEMEngine(alert_callbacks=[received.append])
        event = make_event("Failed password for root from 1.2.3.4 port 22")
        engine.process_event(event)
        assert len(received) >= 1

    def test_builtin_rules_count(self) -> None:
        assert len(BUILTIN_RULES) >= 6


class TestGetParser:
    def test_known_parsers(self) -> None:
        for name in ("syslog", "apache", "generic"):
            p = get_parser(name)
            assert p is not None

    def test_unknown_returns_generic(self) -> None:
        p = get_parser("nonexistent")
        assert p is not None
