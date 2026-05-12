"""Tests for project 60 process logger core."""

from __future__ import annotations

from project_60.core import (
    ProcessInfo,
    build_process_tree,
    detect_anomalies,
)


def _proc(pid: int, ppid: int, name: str, exe: str = "", username: str = "user",
          connections: int = 0) -> ProcessInfo:
    return ProcessInfo(
        pid=pid, ppid=ppid, name=name, exe=exe,
        cmdline=[name], username=username, create_time=0.0,
        status="running", cpu_percent=0.0, memory_rss=0,
        open_files=[], connections=connections,
    )


class TestBuildProcessTree:
    def test_basic_tree(self) -> None:
        procs = [_proc(1, 0, "init"), _proc(100, 1, "bash")]
        roots = build_process_tree(procs)
        init_nodes = [r for r in roots if r.info.pid == 1]
        assert len(init_nodes) == 1
        assert any(c.info.pid == 100 for c in init_nodes[0].children)

    def test_orphan_is_root(self) -> None:
        procs = [_proc(999, 888, "orphan")]
        roots = build_process_tree(procs)
        assert any(r.info.pid == 999 for r in roots)

    def test_render_lines(self) -> None:
        procs = [_proc(1, 0, "init"), _proc(10, 1, "bash")]
        roots = build_process_tree(procs)
        root = next(r for r in roots if r.info.pid == 1)
        lines = root.render()
        assert any("init" in l for l in lines)
        assert any("bash" in l for l in lines)


class TestDetectAnomalies:
    def test_suspicious_parent_child(self) -> None:
        procs = [
            _proc(1, 0, "init"),
            _proc(100, 1, "apache2"),
            _proc(200, 100, "bash"),
        ]
        alerts = detect_anomalies(procs)
        high = [a for a in alerts if a.severity == "high" and a.pid == 200]
        assert len(high) == 1
        assert "apache2" in high[0].reason

    def test_suspicious_exe_path(self) -> None:
        procs = [_proc(500, 1, "x", exe="/tmp/evil")]
        alerts = detect_anomalies(procs)
        assert any(a.severity == "high" and "tmp" in a.reason for a in alerts)

    def test_high_connections(self) -> None:
        procs = [_proc(600, 1, "myapp", connections=60)]
        alerts = detect_anomalies(procs)
        assert any("connection" in a.reason.lower() for a in alerts)

    def test_clean_process_no_alert(self) -> None:
        procs = [_proc(1, 0, "systemd"), _proc(2, 1, "nginx")]
        alerts = detect_anomalies(procs)
        assert alerts == []

    def test_shell_medium_severity(self) -> None:
        procs = [_proc(1, 0, "init"), _proc(200, 1, "nc")]
        alerts = detect_anomalies(procs)
        assert any(a.pid == 200 for a in alerts)
