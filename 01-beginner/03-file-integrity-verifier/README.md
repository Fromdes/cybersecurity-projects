# Project 03 — File Integrity Verifier

> Detect unauthorized file modifications with cryptographic baselines — a lightweight Tripwire.

## What Attack Does This Defend Against?

| MITRE ATT&CK | Technique |
|---|---|
| T1565.001 | Stored Data Manipulation |
| T1070.004 | Indicator Removal: File Deletion |
| T1036 | Masquerading |

Attackers modify config files, binaries, and web content. This tool detects the change.

## Features

- **Init** — walk a directory tree, hash every file (SHA-256), save JSON baseline
- **Check** — re-hash all files, report new / deleted / modified with colored output
- Exclude specific filenames from monitoring
- JSON output for SIEM/pipeline integration
- Handles deep directory trees; streams large files

## Tech Stack

- Python 3.11+, stdlib only (`hashlib`, `json`, `pathlib`, `dataclasses`)

## Architecture

```
cli.py  ──► core.py
             ├── create_baseline()  → dict[path, sha256]
             ├── check_integrity()  → IntegrityReport
             ├── save_baseline()    → JSON file
             └── load_baseline()    → dict
```

## Threat Model (STRIDE)

| Threat | Notes |
|---|---|
| Tampering | Core defence — SHA-256 mismatch reveals any modification |
| Repudiation | Baseline JSON should itself be signed (see Project 09) |
| Information Disclosure | Baseline reveals file names — store securely |

## Install & Run on Kali

```bash
cd 01-beginner/03-file-integrity-verifier
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

# Create baseline of /etc
fim init /etc --output /var/lib/fim/etc.json --exclude passwd.lock

# Check for changes
fim check /etc --baseline /var/lib/fim/etc.json

# Machine-readable output
fim check /etc --baseline /var/lib/fim/etc.json --json
```

## Privileges

`root` required only to read root-owned files. Regular user for user-space directories.

## Example Output

```
CHANGED — 1 modified, 1 deleted
  [MODIFIED] nginx/nginx.conf
  [DELETED]  cron.d/backup
```

## Testing

```bash
pip install -r requirements.txt
pytest --cov=src --cov-report=term-missing
```

## What You'll Learn

- SHA-256 streaming for large-file integrity
- JSON baseline persistence and versioning
- `dataclasses.dataclass(frozen=True)` for immutable report objects
- Incremental change detection strategies

## References

- [MITRE T1565](https://attack.mitre.org/techniques/T1565/)
- [Tripwire open-source](https://github.com/Tripwire/tripwire-open-source)
- [CIS Benchmark — file integrity monitoring](https://www.cisecurity.org/)
