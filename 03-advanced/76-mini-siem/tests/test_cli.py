"""Tests for Mini SIEM Platform CLI."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from project_76.cli import cli


def make_log(tmp_path: Path, content: str) -> Path:
    log = tmp_path / "test.log"
    log.write_text(content)
    return log


class TestIngestCommand:
    def test_ingest_with_alerts(self, tmp_path: Path) -> None:
        log = make_log(tmp_path, "Failed password for root from 1.2.3.4 port 22\n")
        runner = CliRunner()
        result = runner.invoke(cli, ["ingest", str(log), "--parser", "generic"])
        assert result.exit_code == 0
        assert "alert" in result.output.lower()

    def test_ingest_no_alerts(self, tmp_path: Path) -> None:
        log = make_log(tmp_path, "System startup complete\n")
        runner = CliRunner()
        result = runner.invoke(cli, ["ingest", str(log), "--parser", "generic"])
        assert result.exit_code == 0
        assert "0 alert" in result.output

    def test_ingest_output_file(self, tmp_path: Path) -> None:
        log = make_log(tmp_path, "Failed password for root from 1.2.3.4 port 22\n")
        out = tmp_path / "alerts.jsonl"
        runner = CliRunner()
        result = runner.invoke(cli, ["ingest", str(log), "--parser", "generic", "-o", str(out)])
        assert result.exit_code == 0


class TestRulesCommand:
    def test_rules_output(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["rules"])
        assert result.exit_code == 0
        assert "SSH_BRUTE_FORCE" in result.output
        assert "CRITICAL" in result.output or "HIGH" in result.output


class TestSummaryCommand:
    def test_summary(self, tmp_path: Path) -> None:
        import json
        from datetime import datetime, timezone

        alerts_file = tmp_path / "alerts.jsonl"
        records = [
            {"alert_id": "1", "rule_name": "R1", "severity": "HIGH", "message": "m",
             "triggered_at": datetime.now(timezone.utc).isoformat(),
             "event": {"event_id": "e1", "timestamp": datetime.now(timezone.utc).isoformat(),
                       "source": "test", "message": "msg"}},
            {"alert_id": "2", "rule_name": "R2", "severity": "MEDIUM", "message": "m2",
             "triggered_at": datetime.now(timezone.utc).isoformat(),
             "event": {"event_id": "e2", "timestamp": datetime.now(timezone.utc).isoformat(),
                       "source": "test", "message": "msg2"}},
        ]
        alerts_file.write_text("\n".join(json.dumps(r) for r in records) + "\n")
        runner = CliRunner()
        result = runner.invoke(cli, ["summary", str(alerts_file)])
        assert result.exit_code == 0
        assert "Total alerts: 2" in result.output
