"""Process snapshot, tree building, and anomaly detection via psutil."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Final

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SUSPICIOUS_NAMES: Final[frozenset[str]] = frozenset({
    "nc", "netcat", "ncat", "socat", "bash", "sh", "dash",
    "python", "python3", "perl", "ruby", "wget", "curl",
    "xterm", "xterm-256color", "mshta", "wscript", "cscript",
})

SUSPICIOUS_PARENT_CHILD: Final[frozenset[tuple[str, str]]] = frozenset({
    ("apache2", "bash"), ("nginx", "sh"), ("httpd", "bash"),
    ("php-fpm", "bash"), ("php", "bash"),
    ("sshd", "bash"),  # suspicious if not interactive
})

MAX_TREE_DEPTH: Final[int] = 20


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class ProcessInfo:
    """Snapshot of a running process."""

    pid: int
    ppid: int
    name: str
    exe: str
    cmdline: list[str]
    username: str
    create_time: float
    status: str
    cpu_percent: float
    memory_rss: int       # bytes
    open_files: list[str]
    connections: int

    def cmdline_str(self) -> str:
        return " ".join(self.cmdline)


@dataclass
class ProcessNode:
    """Node in the process tree."""

    info: ProcessInfo
    children: list[ProcessNode] = field(default_factory=list)
    depth: int = 0

    def render(self, indent: int = 0) -> list[str]:
        prefix = "  " * indent
        line = f"{prefix}[{self.info.pid}] {self.info.name} ({self.info.username})"
        lines = [line]
        for child in self.children:
            lines.extend(child.render(indent + 1))
        return lines


@dataclass
class ProcessAnomalyAlert:
    """Detected process anomaly."""

    pid: int
    name: str
    reason: str
    severity: str  # "low" | "medium" | "high"


# ---------------------------------------------------------------------------
# Snapshot collector
# ---------------------------------------------------------------------------

def collect_processes() -> list[ProcessInfo]:
    """Collect a snapshot of all running processes via psutil."""
    try:
        import psutil
    except ImportError as exc:
        raise ImportError("pip install psutil") from exc

    procs: list[ProcessInfo] = []
    for proc in psutil.process_iter(
        ["pid", "ppid", "name", "exe", "cmdline", "username",
         "create_time", "status", "cpu_percent", "memory_info"]
    ):
        try:
            info = proc.info
            mem = info.get("memory_info")
            rss = mem.rss if mem else 0

            try:
                open_files = [f.path for f in proc.open_files()]
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                open_files = []

            try:
                connections = len(proc.connections())
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                connections = 0

            procs.append(ProcessInfo(
                pid=info["pid"] or 0,
                ppid=info["ppid"] or 0,
                name=info["name"] or "",
                exe=info.get("exe") or "",
                cmdline=info.get("cmdline") or [],
                username=info.get("username") or "",
                create_time=info.get("create_time") or 0.0,
                status=info.get("status") or "",
                cpu_percent=info.get("cpu_percent") or 0.0,
                memory_rss=rss,
                open_files=open_files,
                connections=connections,
            ))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return procs


# ---------------------------------------------------------------------------
# Tree builder
# ---------------------------------------------------------------------------

def build_process_tree(procs: list[ProcessInfo]) -> list[ProcessNode]:
    """Build process forest from a flat list of ProcessInfo."""
    pid_map: dict[int, ProcessNode] = {p.pid: ProcessNode(info=p) for p in procs}
    roots: list[ProcessNode] = []

    for node in pid_map.values():
        parent = pid_map.get(node.info.ppid)
        if parent and parent is not node:
            parent.children.append(node)
            node.depth = parent.depth + 1
        else:
            roots.append(node)

    return roots


# ---------------------------------------------------------------------------
# Anomaly detector
# ---------------------------------------------------------------------------

def detect_anomalies(procs: list[ProcessInfo]) -> list[ProcessAnomalyAlert]:
    """Return a list of process anomaly alerts."""
    alerts: list[ProcessAnomalyAlert] = []
    pid_map = {p.pid: p for p in procs}

    for proc in procs:
        # Suspicious process names
        if proc.name.lower() in SUSPICIOUS_NAMES:
            parent = pid_map.get(proc.ppid)
            parent_name = parent.name.lower() if parent else ""
            pair = (parent_name, proc.name.lower())

            if pair in SUSPICIOUS_PARENT_CHILD:
                alerts.append(ProcessAnomalyAlert(
                    pid=proc.pid, name=proc.name,
                    reason=f"Suspicious parent-child: {parent_name} → {proc.name}",
                    severity="high",
                ))
            else:
                alerts.append(ProcessAnomalyAlert(
                    pid=proc.pid, name=proc.name,
                    reason=f"Shell/interpreter process: {proc.name}",
                    severity="medium",
                ))

        # Processes with high connection count
        if proc.connections > 50:
            alerts.append(ProcessAnomalyAlert(
                pid=proc.pid, name=proc.name,
                reason=f"High connection count: {proc.connections}",
                severity="medium",
            ))

        # Process running from /tmp or /dev/shm
        exe_lower = proc.exe.lower()
        if exe_lower and any(exe_lower.startswith(p) for p in ("/tmp/", "/dev/shm/")):
            alerts.append(ProcessAnomalyAlert(
                pid=proc.pid, name=proc.name,
                reason=f"Executable in suspicious path: {proc.exe}",
                severity="high",
            ))

    return alerts
