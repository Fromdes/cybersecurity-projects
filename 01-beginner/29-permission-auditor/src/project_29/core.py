"""Directory permission auditing for world-writable, SUID, and SGID files."""
from __future__ import annotations

import logging
import os
import stat
from dataclasses import dataclass
from enum import Enum

log = logging.getLogger(__name__)

WORLD_WRITE_MASK: int = 0o002
WORLD_EXEC_MASK: int = 0o001
SUID_MASK: int = 0o4000
SGID_MASK: int = 0o2000
STICKY_MASK: int = 0o1000
GROUP_WRITE_MASK: int = 0o020


class IssueType(str, Enum):
    """Category of permission issue detected."""

    WORLD_WRITABLE = "world_writable"
    SUID = "suid_bit"
    SGID = "sgid_bit"
    WORLD_EXECUTABLE = "world_executable"
    GROUP_WRITABLE = "group_writable"
    STICKY_NOT_SET = "sticky_not_set_on_dir"


SEVERITY: dict[IssueType, str] = {
    IssueType.WORLD_WRITABLE: "HIGH",
    IssueType.SUID: "HIGH",
    IssueType.SGID: "MEDIUM",
    IssueType.WORLD_EXECUTABLE: "LOW",
    IssueType.GROUP_WRITABLE: "LOW",
    IssueType.STICKY_NOT_SET: "MEDIUM",
}


@dataclass(frozen=True)
class PermissionIssue:
    """A single permission issue found on a file or directory."""

    path: str
    issue_type: IssueType
    mode_octal: str
    severity: str


def audit_path(path: str, recursive: bool = True) -> list[PermissionIssue]:
    """Audit *path* for insecure permission settings.

    Args:
        path: File or directory to audit.
        recursive: Whether to recurse into subdirectories.

    Returns:
        List of PermissionIssue objects found.

    Raises:
        FileNotFoundError: If *path* does not exist.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Path not found: {path!r}")
    issues: list[PermissionIssue] = []
    if os.path.isfile(path):
        issues.extend(_check_path(path))
        return issues
    for dirpath, dirnames, filenames in os.walk(path):
        issues.extend(_check_path(dirpath))
        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            issues.extend(_check_path(fpath))
        if not recursive:
            dirnames.clear()
    return issues


def _check_path(path: str) -> list[PermissionIssue]:
    try:
        mode = os.stat(path).st_mode
    except OSError as exc:
        log.debug("Cannot stat %s: %s", path, exc)
        return []
    is_dir = stat.S_ISDIR(mode)
    mode_int = stat.S_IMODE(mode)
    issues: list[PermissionIssue] = []
    _check_world_write(path, mode_int, issues)
    _check_suid_sgid(path, mode_int, issues)
    if is_dir and (mode_int & WORLD_WRITE_MASK) and not (mode_int & STICKY_MASK):
        _add(path, mode_int, IssueType.STICKY_NOT_SET, issues)
    if not is_dir and (mode_int & WORLD_EXEC_MASK):
        _add(path, mode_int, IssueType.WORLD_EXECUTABLE, issues)
    if mode_int & GROUP_WRITE_MASK:
        _add(path, mode_int, IssueType.GROUP_WRITABLE, issues)
    return issues


def _check_world_write(path: str, mode: int, issues: list[PermissionIssue]) -> None:
    if mode & WORLD_WRITE_MASK:
        _add(path, mode, IssueType.WORLD_WRITABLE, issues)


def _check_suid_sgid(path: str, mode: int, issues: list[PermissionIssue]) -> None:
    if mode & SUID_MASK:
        _add(path, mode, IssueType.SUID, issues)
    if mode & SGID_MASK:
        _add(path, mode, IssueType.SGID, issues)


def _add(path: str, mode: int, issue: IssueType, out: list[PermissionIssue]) -> None:
    out.append(PermissionIssue(
        path=path, issue_type=issue,
        mode_octal=oct(mode), severity=SEVERITY[issue],
    ))
