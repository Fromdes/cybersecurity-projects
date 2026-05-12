"""Tests for project 51 core module."""

from __future__ import annotations

import json
import logging
import tempfile
from pathlib import Path

import pytest

from project_51.core import (
    REDACT_PLACEHOLDER,
    StructuredFormatter,
    get_structured_logger,
    redact_dict,
)


class TestRedactDict:
    def test_redacts_password(self) -> None:
        result = redact_dict({"password": "secret123"})
        assert result["password"] == REDACT_PLACEHOLDER

    def test_redacts_token(self) -> None:
        result = redact_dict({"token": "abc.def.ghi"})
        assert result["token"] == REDACT_PLACEHOLDER

    def test_preserves_normal_fields(self) -> None:
        result = redact_dict({"username": "alice", "age": 30})
        assert result["username"] == "alice"
        assert result["age"] == 30

    def test_redacts_nested(self) -> None:
        result = redact_dict({"user": {"password": "x", "name": "alice"}})
        assert result["user"]["password"] == REDACT_PLACEHOLDER
        assert result["user"]["name"] == "alice"

    def test_redacts_email_in_string(self) -> None:
        result = redact_dict({"message": "Contact alice@example.com for help"})
        assert "alice@example.com" not in result["message"]
        assert "[email]" in result["message"]

    def test_redacts_credit_card(self) -> None:
        result = redact_dict({"info": "Card: 1234 5678 9012 3456"})
        assert "1234 5678 9012 3456" not in result["info"]

    def test_list_of_dicts(self) -> None:
        result = redact_dict({"items": [{"secret": "x"}, {"name": "y"}]})
        assert result["items"][0]["secret"] == REDACT_PLACEHOLDER
        assert result["items"][1]["name"] == "y"


class TestStructuredFormatter:
    def _make_record(self, msg: str, level: int = logging.INFO) -> logging.LogRecord:
        return logging.LogRecord(
            name="test", level=level, pathname="", lineno=0,
            msg=msg, args=(), exc_info=None,
        )

    def test_output_is_valid_json(self) -> None:
        fmt = StructuredFormatter(service_name="svc", environment="test")
        record = self._make_record("hello world")
        output = fmt.format(record)
        data = json.loads(output)
        assert data["message"] == "hello world"
        assert data["service"] == "svc"
        assert data["environment"] == "test"

    def test_level_present(self) -> None:
        fmt = StructuredFormatter()
        record = self._make_record("test", logging.WARNING)
        data = json.loads(fmt.format(record))
        assert data["level"] == "WARNING"

    def test_exception_included(self) -> None:
        fmt = StructuredFormatter()
        try:
            raise ValueError("boom")
        except ValueError:
            import sys
            record = logging.LogRecord(
                name="test", level=logging.ERROR, pathname="", lineno=0,
                msg="error", args=(), exc_info=sys.exc_info(),
            )
        output = fmt.format(record)
        data = json.loads(output)
        assert "exception" in data
        assert "boom" in data["exception"]


class TestGetStructuredLogger:
    def test_returns_logger(self) -> None:
        log = get_structured_logger("test-logger")
        assert isinstance(log, logging.Logger)

    def test_writes_to_file(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as f:
            path = f.name
        log = get_structured_logger(f"file-test-{path}", log_file=path)
        log.info("test message")
        content = Path(path).read_text()
        assert "test message" in content
        data = json.loads(content.strip())
        assert data["level"] == "INFO"
