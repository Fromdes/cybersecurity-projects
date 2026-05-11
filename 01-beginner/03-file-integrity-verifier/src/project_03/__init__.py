"""File Integrity Verifier — create baselines and detect unauthorized file changes."""

from project_03.core import (
    IntegrityReport,
    create_baseline,
    check_integrity,
    load_baseline,
    save_baseline,
)

__all__ = [
    "IntegrityReport",
    "create_baseline",
    "check_integrity",
    "load_baseline",
    "save_baseline",
]
__version__ = "0.1.0"
