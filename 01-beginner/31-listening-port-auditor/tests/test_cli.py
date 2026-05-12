"""Tests for project_31.cli — Listening Port Auditor CLI."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from project_31.cli import _entry_to_dict, main
from project_31.core import PortEntry


def _make_entry(port: int = 22, risk_level: str = "HIGH", risk_score: int = 60) -> PortEntry:
    return PortEntry(
        port=port, protocol="tcp", local_address="0.0.0.0",
        pid=1, process_name="sshd", username="root",
        service_guess="ssh", risk_score=risk_score,
        risk_level=risk_level, risk_flags=("bound to all interfaces",),
    )


class TestEntryToDict:
    def test_all_keys_present(self) -> None:
        d = _entry_to_dict(_make_entry())
        expected = {"port", "protocol", "local_address", "pid", "process_name",
                    "username", "service_guess", "risk_score", "risk_level", "risk_flags"}
        assert expected == set(d.keys())

    def test_risk_flags_is_list(self) -> None:
        d = _entry_to_dict(_make_entry())
        assert isinstance(d["risk_flags"], list)


class TestMain:
    @patch("project_31.cli.list_listening_ports")
    @patch("project_31.cli.filter_by_risk")
    def test_human_output(
        self, mock_filter: MagicMock, mock_list: MagicMock, capsys: pytest.CaptureFixture[str]
    ) -> None:
        mock_list.return_value = [_make_entry()]
        mock_filter.return_value = [_make_entry()]
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code in (None, 0)

    @patch("project_31.cli.list_listening_ports")
    @patch("project_31.cli.filter_by_risk")
    def test_json_output(
        self, mock_filter: MagicMock, mock_list: MagicMock, capsys: pytest.CaptureFixture[str]
    ) -> None:
        mock_list.return_value = [_make_entry()]
        mock_filter.return_value = [_make_entry()]
        with patch("sys.argv", ["port-auditor", "--json"]):
            main()
        captured = capsys.readouterr()
        import json
        data = json.loads(captured.out)
        assert isinstance(data, list)

    @patch("project_31.cli.list_listening_ports")
    @patch("project_31.cli.filter_by_risk")
    def test_empty_entries_message(
        self, mock_filter: MagicMock, mock_list: MagicMock, capsys: pytest.CaptureFixture[str]
    ) -> None:
        mock_list.return_value = []
        mock_filter.return_value = []
        with patch("sys.argv", ["port-auditor"]):
            main()
        captured = capsys.readouterr()
        assert "No listening ports" in captured.out

    @patch("project_31.cli.list_listening_ports", side_effect=ValueError("bad proto"))
    def test_invalid_protocol_exits(
        self, mock_list: MagicMock, capsys: pytest.CaptureFixture[str]
    ) -> None:
        with patch("sys.argv", ["port-auditor", "--protocol", "tcp"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
        assert exc_info.value.code == 1
