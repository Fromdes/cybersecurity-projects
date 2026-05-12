"""Tests for project_32.cli — Hosts File Tamper Detector CLI."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from project_32.cli import main

SAMPLE_HOSTS = "127.0.0.1 localhost\n192.168.1.1 router\n"


class TestCLIBaseline:
    def test_baseline_command(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        hosts = tmp_path / "hosts"
        hosts.write_text(SAMPLE_HOSTS)
        baseline = tmp_path / "baseline.json"
        with patch("sys.argv", ["hosts-tamper-detect", "--hosts", str(hosts),
                                "--baseline", str(baseline), "baseline"]):
            main()
        captured = capsys.readouterr()
        assert "Baseline saved" in captured.out
        assert baseline.exists()


class TestCLICheck:
    def test_check_no_tampering(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        hosts = tmp_path / "hosts"
        hosts.write_text(SAMPLE_HOSTS)
        baseline = tmp_path / "baseline.json"
        with patch("sys.argv", ["hosts-tamper-detect", "--hosts", str(hosts),
                                "--baseline", str(baseline), "baseline"]):
            main()
        with patch("sys.argv", ["hosts-tamper-detect", "--hosts", str(hosts),
                                "--baseline", str(baseline), "check"]):
            main()
        captured = capsys.readouterr()
        assert "OK" in captured.out

    def test_check_detects_tampering(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        hosts = tmp_path / "hosts"
        hosts.write_text(SAMPLE_HOSTS)
        baseline = tmp_path / "baseline.json"
        with patch("sys.argv", ["hosts-tamper-detect", "--hosts", str(hosts),
                                "--baseline", str(baseline), "baseline"]):
            main()
        hosts.write_text(SAMPLE_HOSTS + "1.2.3.4 paypal.com\n")
        with patch("sys.argv", ["hosts-tamper-detect", "--hosts", str(hosts),
                                "--baseline", str(baseline), "check"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
        assert exc_info.value.code == 2

    def test_check_missing_baseline_exits(self, tmp_path: Path) -> None:
        hosts = tmp_path / "hosts"
        hosts.write_text(SAMPLE_HOSTS)
        with patch("sys.argv", ["hosts-tamper-detect", "--hosts", str(hosts),
                                "--baseline", str(tmp_path / "missing.json"), "check"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
        assert exc_info.value.code == 1


class TestCLIShow:
    def test_show_command(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        hosts = tmp_path / "hosts"
        hosts.write_text(SAMPLE_HOSTS)
        with patch("sys.argv", ["hosts-tamper-detect", "--hosts", str(hosts),
                                "--baseline", str(tmp_path / "b.json"), "show"]):
            main()
        captured = capsys.readouterr()
        assert "localhost" in captured.out
