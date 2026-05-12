# Project 55 — YARA Rule Engine Orchestrator

> Compile YARA rule sets, scan files and directories for malware patterns, and generate structured match reports.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Description |
|---|---|---|
| Malicious File | T1204.002 | YARA detects known malware byte patterns and strings |
| Ingress Tool Transfer | T1105 | Scan incoming files against IOC signatures |
| Masquerading | T1036 | Content-based detection ignores file extension |

## Features

- `RuleLoader` — discovers and compiles `.yar`/`.yara` files from a directory
- `YARAScanner` — scans single files or directory trees
- Structured `ScanReport` with match details (rule, namespace, tags, meta, string offsets)
- File size limit to skip oversized targets
- Soft dependency on `yara-python` (tests mock it)
- CLI: `scan`, `list-rules`

## Install & Run

```bash
cd 02-intermediate/55-yara-orchestrator
pip install -e .
pip install yara-python       # optional; needed for live scanning
yara-orchestrator list-rules --rules-dir examples/rules
yara-orchestrator scan /path/to/target --rules-dir examples/rules
```

## Testing

```bash
pytest tests/ -v --cov=project_55
# Tests run without yara-python via built-in stub
```

## What You'll Learn

- YARA rule syntax (strings, conditions, meta, tags)
- Compiling and matching YARA rules in Python
- File scanning orchestration patterns
- Mocking C-extension libraries in pytest
