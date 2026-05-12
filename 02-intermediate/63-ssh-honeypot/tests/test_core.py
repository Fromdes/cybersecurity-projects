"""Tests for project 63 SSH honeypot core."""

from __future__ import annotations

import socket
import threading
import time

from project_63.core import (
    HoneypotEvent,
    HoneypotLogger,
    SSHHoneypotServer,
)


class TestHoneypotLogger:
    def test_record_and_retrieve(self) -> None:
        hp_logger = HoneypotLogger()
        event = HoneypotEvent(
            timestamp=time.time(), src_ip="10.0.0.1", src_port=12345,
            event_type="connect", session_id="s1",
        )
        hp_logger.record(event)
        events = hp_logger.all_events()
        assert len(events) == 1
        assert events[0].src_ip == "10.0.0.1"

    def test_credential_summary(self) -> None:
        hp_logger = HoneypotLogger()
        for _ in range(3):
            hp_logger.record(HoneypotEvent(
                timestamp=time.time(), src_ip="10.0.0.1", src_port=22,
                event_type="auth_attempt", username="root", password="123456",
                session_id="s1",
            ))
        hp_logger.record(HoneypotEvent(
            timestamp=time.time(), src_ip="10.0.0.2", src_port=22,
            event_type="auth_attempt", username="admin", password="admin",
            session_id="s2",
        ))
        summary = hp_logger.credential_summary()
        assert summary.get("root:123456") == 3

    def test_thread_safety(self) -> None:
        hp_logger = HoneypotLogger()
        def add_events() -> None:
            for i in range(50):
                hp_logger.record(HoneypotEvent(
                    timestamp=time.time(), src_ip=f"10.0.0.{i % 10}", src_port=22,
                    event_type="connect", session_id=f"s{i}",
                ))
        threads = [threading.Thread(target=add_events) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(hp_logger.all_events()) == 200

    def test_writes_to_file(self, tmp_path) -> None:
        import json
        log_file = tmp_path / "hp.jsonl"
        hp_logger = HoneypotLogger(log_path=log_file)
        hp_logger.record(HoneypotEvent(
            timestamp=1234.5, src_ip="1.2.3.4", src_port=22,
            event_type="connect", session_id="s1",
        ))
        lines = log_file.read_text().splitlines()
        assert len(lines) == 1
        data = json.loads(lines[0])
        assert data["src_ip"] == "1.2.3.4"


class TestSSHHoneypotServer:
    def test_banner_sent(self) -> None:
        """Start server, connect, verify SSH banner received."""
        hp_logger = HoneypotLogger()
        server = SSHHoneypotServer(host="127.0.0.1", port=0, honeypot_logger=hp_logger)
        # Bind to random port
        srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv_sock.bind(("127.0.0.1", 0))
        port = srv_sock.getsockname()[1]
        srv_sock.close()

        server.port = port
        server.start(blocking=False)
        time.sleep(0.2)

        try:
            with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
                data = sock.recv(256)
                assert data.startswith(b"SSH-2.0")
        finally:
            server.stop()

    def test_connect_event_recorded(self) -> None:
        hp_logger = HoneypotLogger()

        srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv_sock.bind(("127.0.0.1", 0))
        port = srv_sock.getsockname()[1]
        srv_sock.close()

        server = SSHHoneypotServer(host="127.0.0.1", port=port, honeypot_logger=hp_logger)
        server.start(blocking=False)
        time.sleep(0.2)

        try:
            with socket.create_connection(("127.0.0.1", port), timeout=2):
                time.sleep(0.3)
        finally:
            server.stop()

        events = hp_logger.all_events()
        assert any(e.event_type == "connect" for e in events)
