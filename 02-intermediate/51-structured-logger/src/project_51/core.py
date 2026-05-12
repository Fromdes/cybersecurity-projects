"""Structured JSON log formatter, sensitive field redactor, and log router."""

from __future__ import annotations

import logging
import re
import time
import traceback
from dataclasses import dataclass
from io import StringIO
from typing import Any, Final

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REDACT_PLACEHOLDER: Final[str] = "***REDACTED***"

SENSITIVE_KEYS: Final[frozenset[str]] = frozenset({
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "authorization", "auth", "credential", "credit_card", "ssn",
    "private_key", "access_token", "refresh_token",
})

_EMAIL_RE: Final[re.Pattern[str]] = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
)
_CREDIT_CARD_RE: Final[re.Pattern[str]] = re.compile(r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b")


# ---------------------------------------------------------------------------
# Redactor
# ---------------------------------------------------------------------------

def redact_dict(data: dict[str, Any], *, depth: int = 0) -> dict[str, Any]:
    """Recursively redact sensitive keys and patterns from a dict."""
    if depth > 10:
        return data
    result: dict[str, Any] = {}
    for k, v in data.items():
        if k.lower() in SENSITIVE_KEYS:
            result[k] = REDACT_PLACEHOLDER
        elif isinstance(v, dict):
            result[k] = redact_dict(v, depth=depth + 1)
        elif isinstance(v, list):
            result[k] = [redact_dict(i, depth=depth + 1) if isinstance(i, dict) else i for i in v]
        elif isinstance(v, str):
            v = _EMAIL_RE.sub("[email]", v)
            v = _CREDIT_CARD_RE.sub("[card]", v)
            result[k] = v
        else:
            result[k] = v
    return result


# ---------------------------------------------------------------------------
# JSON formatter
# ---------------------------------------------------------------------------

class StructuredFormatter(logging.Formatter):
    """Emit log records as single-line JSON."""

    def __init__(
        self,
        service_name: str = "app",
        environment: str = "development",
        extra_fields: dict[str, Any] | None = None,
    ) -> None:
        super().__init__()
        self._service = service_name
        self._env = environment
        self._extra = extra_fields or {}

    def format(self, record: logging.LogRecord) -> str:
        import json

        exc_text = ""
        if record.exc_info:
            sio = StringIO()
            traceback.print_exception(*record.exc_info, file=sio)
            exc_text = sio.getvalue().rstrip()

        payload: dict[str, Any] = {
            "timestamp": time.strftime(
                "%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)
            ) + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "service": self._service,
            "environment": self._env,
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        if exc_text:
            payload["exception"] = exc_text

        # Merge extra context attached to the record
        for key, val in vars(record).items():
            if key not in {
                "name", "msg", "args", "levelname", "levelno", "pathname",
                "filename", "module", "exc_info", "exc_text", "stack_info",
                "lineno", "funcName", "created", "msecs", "relativeCreated",
                "thread", "threadName", "processName", "process", "message",
                "taskName",
            } and not key.startswith("_"):
                payload[key] = val

        payload.update(self._extra)
        payload = redact_dict(payload)
        return json.dumps(payload, default=str)


# ---------------------------------------------------------------------------
# Logger factory
# ---------------------------------------------------------------------------

def get_structured_logger(
    name: str,
    *,
    level: int = logging.DEBUG,
    service_name: str = "app",
    environment: str = "development",
    log_file: str | None = None,
) -> logging.Logger:
    """Return a logger configured with StructuredFormatter."""
    log = logging.getLogger(name)
    log.setLevel(level)

    if not log.handlers:
        handler: logging.Handler = (
            logging.FileHandler(log_file, encoding="utf-8")
            if log_file
            else logging.StreamHandler()
        )
        handler.setFormatter(
            StructuredFormatter(service_name=service_name, environment=environment)
        )
        log.addHandler(handler)

    return log


# ---------------------------------------------------------------------------
# Log level sampler (for high-volume scenarios)
# ---------------------------------------------------------------------------

@dataclass
class SamplingFilter(logging.Filter):
    """Drop DEBUG/INFO records with configurable probability."""

    sample_rate: float = 1.0  # 1.0 = keep all, 0.1 = keep 10%

    def filter(self, record: logging.LogRecord) -> bool:
        import random
        if record.levelno >= logging.WARNING:
            return True
        return random.random() < self.sample_rate  # noqa: S311
