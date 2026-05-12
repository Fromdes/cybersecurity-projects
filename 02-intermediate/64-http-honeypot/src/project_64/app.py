"""Flask-based HTTP honeypot server."""

from __future__ import annotations

import time
import uuid

from flask import Flask, Response, jsonify, request

from .core import HTTPHoneypotLogger, HTTPRequest, classify_request

_honeypot_logger = HTTPHoneypotLogger()

app = Flask(__name__)


def _capture_request() -> None:
    req = HTTPRequest(
        timestamp=time.time(),
        src_ip=request.remote_addr or "0.0.0.0",
        src_port=0,
        method=request.method,
        path=request.path,
        query_string=request.query_string.decode(errors="replace"),
        http_version=request.environ.get("SERVER_PROTOCOL", "HTTP/1.1"),
        headers=dict(request.headers),
        body=request.get_data(as_text=True)[:4096],
        session_id=str(uuid.uuid4()),
    )
    tc = classify_request(req)
    _honeypot_logger.record(tc)


@app.before_request
def log_request() -> None:
    _capture_request()


@app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
def catch_all(path: str) -> Response:
    """Return a generic 404 for everything."""
    return Response("Not Found", status=404, mimetype="text/plain")


@app.route("/_honeypot/stats")
def stats() -> Response:
    """Internal stats endpoint (bind to localhost only in production)."""
    return jsonify(_honeypot_logger.threat_summary())
