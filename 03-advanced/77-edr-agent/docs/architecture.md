# Architecture — Lightweight EDR Agent

## Detection Pipeline

1. `snapshot_processes()` — iterates psutil, produces `ProcessSnapshot` frozen dataclasses.
2. Per-snapshot detectors — pure functions, each returns `Finding | None`.
3. System-level detectors — `detect_suspicious_listening_ports()`, `detect_hidden_processes()`.
4. `EDRAgent` orchestrates all detectors, records findings to JSONL, exposes summary.

## Extension

- Add new detector functions following the `(ProcessSnapshot) -> Finding | None` signature.
- Register in `EDRAgent.scan_once()`.
- Add new suspicious port numbers to `SUSPICIOUS_PORTS` constant.
