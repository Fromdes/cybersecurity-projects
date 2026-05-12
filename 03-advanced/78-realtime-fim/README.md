# Project 78 — Real-Time File Integrity Monitor (inotify)

> Uses inotify (via watchdog) to detect file creation, modification, deletion, and moves in real-time, comparing against a cryptographic SHA-256 baseline.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Description |
|---|---|---|
| Indicator Removal on Host | T1070 | Detects log/evidence file deletion |
| Modify Authentication Process | T1556 | Alerts on /etc/passwd, /etc/shadow changes |
| Boot or Logon Autostart | T1547 | Detects changes to autostart directories |
| Implant Container Image | T1525 | Monitors critical binary paths |
| Data Destruction | T1485 | Detects mass file deletion events |

## Features

- Cryptographic SHA-256 baseline building for files and directories
- Batch verification: compare current state to saved baseline
- Real-time inotify-based monitoring with watchdog
- JSONL event log for SIEM integration
- Recursive or flat directory scanning

## Tech Stack

- Python 3.11+, watchdog, hashlib, click

## Architecture

```
baseline build ──► Baseline (SHA-256 per file) ──► JSON file

verify ──► load baseline ──► compare current hashes ──► FIMEvent list

watch ──► load baseline ──► FIMWatcher (watchdog) ──► FIMEvent callback ──► JSONL
```

## Threat Model (STRIDE)

| STRIDE | Risk | Mitigation |
|---|---|---|
| Tampering | Baseline file modified | Store baseline on read-only medium; sign with HMAC |
| Repudiation | Event log deleted | Append-only JSONL; external log forwarding |
| Info Disclosure | Sensitive paths in event log | Filter path patterns before logging |
| DoS | High-frequency events flood log | Debounce in watchdog handler |
| Elevation | FIM bypassed via kernel module | Kernel-level integrity (IMA/EVM) for full protection |

## Install & Run on Kali

```bash
cd 03-advanced/78-realtime-fim
pip install -e .
realtime-fim baseline /etc /usr/bin --output baseline.json
realtime-fim verify baseline.json
realtime-fim watch baseline.json /etc /usr/bin -o events.jsonl
```

## Privileges

Read access to monitored paths. `/etc/shadow` requires root.

## Example Output

```
Baseline built: 1337 file(s) → baseline.json
[MODIFIED] /etc/hosts
[DELETED]  /var/log/auth.log
```

## Testing

```bash
pytest tests/ -v --cov=project_78
```

## What You'll Learn

- inotify and watchdog event-driven architecture
- Cryptographic file fingerprinting (SHA-256)
- Baseline snapshot and diff patterns

## References

- [inotify man page](https://man7.org/linux/man-pages/man7/inotify.7.html)
- [watchdog docs](https://python-watchdog.readthedocs.io/)
- [MITRE T1070](https://attack.mitre.org/techniques/T1070/)
