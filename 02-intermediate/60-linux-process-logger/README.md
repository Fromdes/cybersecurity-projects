# Project 60 — Linux Process Tree Logger

> Snapshot Linux process trees, detect anomalous parent-child relationships and suspicious executable paths.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Description |
|---|---|---|
| Command and Scripting Interpreter | T1059 | Detect web-server → shell spawn chains |
| Process Injection | T1055 | Spot processes from /tmp or /dev/shm |
| Discovery | T1057 | Baseline process state for deviation detection |

## Features

- `psutil`-powered process snapshot
- Recursive process forest builder
- Anomaly detection: suspicious parent→child pairs, /tmp executables, high connection counts
- Continuous monitoring mode with configurable poll interval
- JSON and tree rendering output

## Install & Run

```bash
cd 02-intermediate/60-linux-process-logger
pip install -e .
process-logger snapshot --tree
process-logger snapshot --anomalies-only
process-logger monitor --interval 10 --log-file /var/log/process-monitor.log
```

## Testing

```bash
pytest tests/ -v --cov=project_60
```

## What You'll Learn

- psutil process API
- Process tree reconstruction from PID/PPID pairs
- Parent-child anomaly patterns (web shell detection)
