# Project 80 — Office Macro Risk Analyzer

> Performs static VBA macro analysis on Office documents (.doc, .xls, .xlsm, etc.) to detect malicious patterns including auto-execution, shell commands, downloads, and obfuscation techniques.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Description |
|---|---|---|
| Phishing: Malicious File | T1566.001 | Detects macro-laced Office documents |
| User Execution: Malicious File | T1204.002 | Flags AutoOpen/Document_Open triggers |
| Command and Scripting: VBScript | T1059.005 | Detects Shell/WScript execution |
| Ingress Tool Transfer | T1105 | Detects URLDownloadToFile/WinHTTP |
| Obfuscated Files | T1027 | Detects Chr() obfuscation and string concatenation |
| Modify Registry | T1112 | Detects RegWrite/RegCreateKey calls |

## Features

- VBA macro extraction via oletools (fallback: regex scan)
- 15 risk indicator categories with MITRE ATT&CK mapping
- Severity-weighted risk scoring (0–100)
- OLE2 and OOXML format support
- Batch analysis mode
- JSON report output

## Tech Stack

- Python 3.11+, oletools, click, re

## Architecture

```
Office File ──► OLE2/OOXML detection
               │
               ├── oletools VBA_Parser ──► VBA source ──► regex scan ──► indicators
               │                                    └── oletools built-in analysis
               └── regex fallback (no oletools) ──► raw byte scan

indicators ──► _score_from_indicators() ──► risk_score ──► MacroAnalysisResult
```

## Threat Model (STRIDE)

| STRIDE | Risk | Mitigation |
|---|---|---|
| Spoofing | Disguised file extension | Magic byte format detection |
| Tampering | Malicious doc modifies analyzer | Run in sandbox; read-only input |
| Repudiation | No audit trail | JSON report with SHA-256 |
| DoS | Large encrypted OLE2 exhausts memory | Size limit before analysis |
| Elevation | Exploit oletools parser | No code execution; static only |

## Install & Run on Kali

```bash
cd 03-advanced/80-office-macro-analyzer
pip install -e .
office-macro-analyzer analyze document.docm
office-macro-analyzer analyze invoice.xlsm -o report.json --show-vba
office-macro-analyzer batch /path/to/docs/ -o batch_report.json
```

## Privileges

No privileges required.

## Example Output

```
File: invoice.xlsm  Format: OOXML  Has macros: True
[CRITICAL] Network download capability (T1105)
           snippet: URLDownloadToFile url, localpath
[HIGH]     Auto-execution trigger (T1204.002)
           snippet: Sub AutoOpen()
[HIGH]     PowerShell invocation (T1059.001)
Risk score: 80
```

## Testing

```bash
pytest tests/ -v --cov=project_80
```

## What You'll Learn

- OLE2 and OOXML Office file formats
- VBA macro static analysis with oletools
- Regex-based behavioral indicator detection

## References

- [oletools documentation](https://github.com/decalage2/oletools)
- [MITRE T1566.001](https://attack.mitre.org/techniques/T1566/001/)
