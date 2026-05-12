# Project 81 — Forensics Timeline Builder

> Collects timestamps from filesystem metadata (mtime/atime/ctime), syslog files, and generic ISO8601 logs, then merges them into a single sorted forensic timeline in JSONL or CSV format.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Description |
|---|---|---|
| Indicator Removal: Timestomp | T1070.006 | Exposes anomalous file timestamp patterns |
| Data from Local System | T1005 | Helps identify accessed/exfiltrated files |
| Lateral Movement (pivot analysis) | T1021 | Correlates login events with file accesses |
| Execution (timeline reconstruction) | T1059 | Reconstructs command execution from logs |

## Features

- Filesystem mtime/atime/ctime collection (recursive or flat)
- Syslog-format log parsing (auth.log, syslog)
- Generic ISO8601 log parsing (application logs)
- Multi-source merge into sorted timeline
- JSONL and CSV output formats
- Time range filtering
- Summary statistics

## Tech Stack

- Python 3.11+, click, csv, json, re, os.stat

## Architecture

```
Sources:
  filesystem paths ──► collect_filesystem_events()
  syslog files     ──► collect_syslog_events()
  generic logs     ──► collect_generic_log_events()
          │
          ▼
  ForensicsTimeline.add_events()
          │
          ▼
  sorted_events() ──► JSONL / CSV
```

## Threat Model (STRIDE)

| STRIDE | Risk | Mitigation |
|---|---|---|
| Tampering | Attacker timestomps files | Cross-reference multiple timestamp sources |
| Repudiation | Log entries deleted | Forensic copy; chain of custody |
| Info Disclosure | Timeline contains sensitive paths | Restrict output file permissions |
| DoS | Large directories exhaust memory | Streaming generator pattern |

## Install & Run on Kali

```bash
cd 03-advanced/81-forensics-timeline
pip install -e .
forensics-timeline build --fs /var/log --syslog /var/log/auth.log -o timeline.jsonl
forensics-timeline build --fs /home --log /var/log/app.log -o timeline.csv --format csv
forensics-timeline summary timeline.jsonl
```

## Privileges

Read access to target paths required. `/var/log/auth.log` may need `adm` group.

## Example Output

```
filesystem /var/log: 247 events
syslog auth.log: 183 events
Timeline built: 430 events → timeline.jsonl
  Earliest: 2024-01-01T00:00:00+00:00
  Latest:   2024-05-12T10:15:33+00:00
  filesystem: 247   syslog: 183
```

## Testing

```bash
pytest tests/ -v --cov=project_81
```

## What You'll Learn

- Filesystem metadata (stat) and forensic timestamps
- Multi-source log correlation for incident response
- Timestomping detection through cross-source analysis

## References

- [MITRE T1070.006](https://attack.mitre.org/techniques/T1070/006/)
- [Sleuth Kit / Autopsy timeline model](https://www.sleuthkit.org/)
