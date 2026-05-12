"""SSH honeypot: accept connections, log credentials, never grant access."""

from __future__ import annotations

import logging
import socket
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BANNER: Final[bytes] = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"
MAX_AUTH_ATTEMPTS: Final[int] = 3
READ_TIMEOUT: Final[float] = 10.0


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class HoneypotEvent:
    """A recorded honeypot interaction."""

    timestamp: float
    src_ip: str
    src_port: int
    event_type: str   # "connect" | "auth_attempt" | "disconnect"
    username: str = ""
    password: str = ""
    client_banner: str = ""
    session_id: str = ""


@dataclass
class HoneypotSession:
    """State for one honeypot connection."""

    session_id: str
    src_ip: str
    src_port: int
    connected_at: float
    events: list[HoneypotEvent] = field(default_factory=list)
    auth_attempts: int = 0


# ---------------------------------------------------------------------------
# Event logger
# ---------------------------------------------------------------------------

@dataclass
class HoneypotLogger:
    """Thread-safe event recorder."""

    log_path: Path | None = None
    _events: list[HoneypotEvent] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def record(self, event: HoneypotEvent) -> None:
        with self._lock:
            self._events.append(event)
        logger.info(
            "honeypot event: type=%s src=%s:%d user=%s",
            event.event_type, event.src_ip, event.src_port, event.username,
        )
        if self.log_path:
            self._write(event)

    def _write(self, event: HoneypotEvent) -> None:
        import json
        line = json.dumps({
            "timestamp": event.timestamp,
            "src_ip": event.src_ip,
            "src_port": event.src_port,
            "event_type": event.event_type,
            "username": event.username,
            "password": event.password,
            "client_banner": event.client_banner,
            "session_id": event.session_id,
        })
        assert self.log_path is not None
        with open(self.log_path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")

    def all_events(self) -> list[HoneypotEvent]:
        with self._lock:
            return list(self._events)

    def credential_summary(self) -> dict[str, int]:
        """Return top attempted credentials (user:pass → count)."""
        counts: dict[str, int] = {}
        for e in self.all_events():
            if e.event_type == "auth_attempt" and e.username:
                key = f"{e.username}:{e.password}"
                counts[key] = counts.get(key, 0) + 1
        return dict(sorted(counts.items(), key=lambda x: x[1], reverse=True)[:20])


# ---------------------------------------------------------------------------
# Honeypot server (paramiko-based with stub for testing)
# ---------------------------------------------------------------------------

def _handle_connection(
    conn: socket.socket,
    addr: tuple[str, int],
    honeypot_logger: HoneypotLogger,
    session_id: str,
) -> None:
    """Handle a single honeypot TCP connection at the raw socket level."""
    src_ip, src_port = addr[0], addr[1]
    try:
        conn.settimeout(READ_TIMEOUT)
        conn.sendall(BANNER)

        honeypot_logger.record(HoneypotEvent(
            timestamp=time.time(), src_ip=src_ip, src_port=src_port,
            event_type="connect", session_id=session_id,
        ))

        # Read client banner
        try:
            client_banner = conn.recv(256).decode(errors="replace").strip()
        except (OSError, TimeoutError):
            client_banner = ""

        if client_banner:
            honeypot_logger.record(HoneypotEvent(
                timestamp=time.time(), src_ip=src_ip, src_port=src_port,
                event_type="banner", client_banner=client_banner,
                session_id=session_id,
            ))

        # Drop connection — do NOT attempt paramiko key exchange here
        # so we avoid any risk of running code on behalf of the attacker.

    except Exception as exc:
        logger.debug("Honeypot connection error: %s", exc)
    finally:
        honeypot_logger.record(HoneypotEvent(
            timestamp=time.time(), src_ip=src_ip, src_port=src_port,
            event_type="disconnect", session_id=session_id,
        ))
        try:
            conn.close()
        except OSError:
            pass


class SSHHoneypotServer:
    """Lightweight SSH banner honeypot (no real SSH negotiation)."""

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 2222,
        *,
        honeypot_logger: HoneypotLogger | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.honeypot_logger = honeypot_logger or HoneypotLogger()
        self._running = False
        self._server_socket: socket.socket | None = None
        self._session_counter = 0

    def start(self, *, blocking: bool = True) -> None:
        """Start the honeypot server."""
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind((self.host, self.port))
        self._server_socket.listen(50)
        self._running = True
        logger.info("SSH honeypot listening on %s:%d", self.host, self.port)

        if blocking:
            self._accept_loop()
        else:
            t = threading.Thread(target=self._accept_loop, daemon=True)
            t.start()

    def stop(self) -> None:
        self._running = False
        if self._server_socket:
            try:
                self._server_socket.close()
            except OSError:
                pass

    def _accept_loop(self) -> None:
        assert self._server_socket is not None
        self._server_socket.settimeout(1.0)
        while self._running:
            try:
                conn, addr = self._server_socket.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            self._session_counter += 1
            sid = f"session-{self._session_counter}"
            t = threading.Thread(
                target=_handle_connection,
                args=(conn, addr, self.honeypot_logger, sid),
                daemon=True,
            )
            t.start()
