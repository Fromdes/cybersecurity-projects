"""Suspicious process detection by scoring process attributes."""
from __future__ import annotations

import logging
from dataclasses import dataclass

import psutil

log = logging.getLogger(__name__)

RISK_HIGH_THRESHOLD: int = 50
RISK_MEDIUM_THRESHOLD: int = 25

SUSPICIOUS_DIRS: frozenset[str] = frozenset({"/tmp", "/var/tmp", "/dev/shm", "/run/shm"})
SCORE_SUSPICIOUS_DIR: int = 40
SCORE_DELETED_EXE: int = 45
SCORE_HIDDEN_NAME: int = 30
SCORE_NO_EXE: int = 20
SCORE_UNUSUAL_CMDLINE: int = 10
CMDLINE_LONG_THRESHOLD: int = 512


@dataclass(frozen=True)
class ProcessInfo:
    """Scored process snapshot."""

    pid: int
    name: str
    exe: str | None
    cmdline: tuple[str, ...]
    username: str
    ppid: int | None
    risk_score: int
    risk_level: str
    risk_flags: tuple[str, ...]


def list_processes() -> list[ProcessInfo]:
    """Snapshot all accessible running processes with risk scores.

    Returns:
        List of ProcessInfo sorted by risk_score descending.
    """
    results: list[ProcessInfo] = []
    for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "username", "ppid"]):
        info = _assess_process(proc)
        if info is not None:
            results.append(info)
    return sorted(results, key=lambda p: p.risk_score, reverse=True)


def get_suspicious(processes: list[ProcessInfo], threshold: int = RISK_MEDIUM_THRESHOLD) -> list[ProcessInfo]:
    """Filter *processes* to those with risk_score >= *threshold*.

    Args:
        processes: List returned by list_processes().
        threshold: Minimum risk score to include.

    Returns:
        Filtered list sorted by risk_score descending.
    """
    return [p for p in processes if p.risk_score >= threshold]


def _assess_process(proc: psutil.Process) -> ProcessInfo | None:
    try:
        info = proc.info  # type: ignore[attr-defined]
        name: str = info.get("name") or ""
        exe: str | None = info.get("exe")
        cmdline: list[str] = info.get("cmdline") or []
        username: str = info.get("username") or "unknown"
        ppid: int | None = info.get("ppid")
        score, flags = _compute_risk(name, exe, cmdline)
        level = _score_to_level(score)
        return ProcessInfo(
            pid=proc.pid, name=name, exe=exe,
            cmdline=tuple(cmdline), username=username, ppid=ppid,
            risk_score=score, risk_level=level, risk_flags=tuple(flags),
        )
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None


def _compute_risk(name: str, exe: str | None, cmdline: list[str]) -> tuple[int, list[str]]:
    score = 0
    flags: list[str] = []
    if name.startswith("."):
        score += SCORE_HIDDEN_NAME
        flags.append("hidden process name (starts with '.')")
    if exe:
        if exe.endswith(" (deleted)"):
            score += SCORE_DELETED_EXE
            flags.append("executable deleted while process running")
        elif any(exe.startswith(d + "/") or exe.startswith(d) for d in SUSPICIOUS_DIRS):
            score += SCORE_SUSPICIOUS_DIR
            flags.append(f"executable in suspicious directory: {exe}")
    elif not cmdline:
        score += SCORE_NO_EXE
        flags.append("no executable path and no command line")
    if cmdline and len(" ".join(cmdline)) > CMDLINE_LONG_THRESHOLD:
        score += SCORE_UNUSUAL_CMDLINE
        flags.append("unusually long command line")
    return score, flags


def _score_to_level(score: int) -> str:
    if score >= RISK_HIGH_THRESHOLD:
        return "HIGH"
    if score >= RISK_MEDIUM_THRESHOLD:
        return "MEDIUM"
    return "LOW"
