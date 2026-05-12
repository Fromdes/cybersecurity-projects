"""Tests for project_98 CLI — Network ML Anomaly Detector."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from project_98.cli import cli


def _csv_content(n_normal: int = 50, include_scan: bool = False) -> str:
    lines = ["src_ip,dst_ip,src_port,dst_port,protocol,bytes_total,packets,duration_ms"]
    for i in range(n_normal):
        # Rotate 3 source IPs and 5 dest IPs to avoid triggering DDoS detector
        lines.append(f"10.0.0.{(i % 3) + 1},10.0.0.{(i % 5) + 10},{1024 + i},80,tcp,1000,10,100")
    if include_scan:
        for p in range(1, 30):
            lines.append(f"10.99.0.1,10.0.0.2,54321,{p},tcp,100,1,10")
    return "\n".join(lines)


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture()
def normal_csv(tmp_path: Path) -> Path:
    f = tmp_path / "normal.csv"
    f.write_text(_csv_content())
    return f


@pytest.fixture()
def scan_csv(tmp_path: Path) -> Path:
    f = tmp_path / "scan.csv"
    f.write_text(_csv_content(include_scan=True))
    return f


class TestAnalyzeCommand:
    def test_analyze_normal_no_anomalies(self, runner: CliRunner, normal_csv: Path) -> None:
        result = runner.invoke(cli, ["analyze", str(normal_csv)])
        assert result.exit_code == 0
        assert "flows" in result.output.lower()

    def test_analyze_scan_detected(self, runner: CliRunner, scan_csv: Path) -> None:
        result = runner.invoke(cli, ["analyze", str(scan_csv), "--port-scan-threshold", "15"])
        assert result.exit_code == 0
        assert "PORT_SCAN" in result.output

    def test_analyze_output_json(self, runner: CliRunner, scan_csv: Path, tmp_path: Path) -> None:
        out = tmp_path / "report.json"
        result = runner.invoke(cli, ["analyze", str(scan_csv), "-o", str(out), "--port-scan-threshold", "15"])
        assert result.exit_code == 0
        assert out.exists()
        data = json.loads(out.read_text())
        assert "anomalies" in data

    def test_exit_code_on_critical(self, runner: CliRunner, scan_csv: Path) -> None:
        result = runner.invoke(cli, ["analyze", str(scan_csv), "--exit-code", "--port-scan-threshold", "15"])
        assert result.exit_code == 1

    def test_no_exit_code_normal(self, runner: CliRunner, normal_csv: Path) -> None:
        result = runner.invoke(cli, ["analyze", str(normal_csv), "--exit-code"])
        assert result.exit_code == 0

    def test_missing_file_error(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["analyze", "/nonexistent/flows.csv"])
        assert result.exit_code != 0


class TestVersionOption:
    def test_version_flag(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output
