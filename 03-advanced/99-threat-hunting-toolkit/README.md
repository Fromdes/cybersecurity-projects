# Project 99 — Threat Hunting Toolkit

> Rule-based threat hunting across log files with 10 built-in MITRE ATT&CK-mapped hunt rules and IOC correlation.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Description |
|---|---|---|
| Command and Scripting Interpreter | T1059 | PowerShell encoded commands, curl\|bash |
| Credential Dumping | T1003.001 | LSASS memory access patterns |
| Scheduled Task/Job | T1053 | schtasks /create, crontab patterns |
| Lateral Movement | T1021 | PsExec, WMI remote execution |
| DNS Tunneling | T1071.004 | Anomalously long DNS query names |

## Built-in Hunt Rules

| Rule | Severity | Pattern |
|---|---|---|
| HUNT-001 | HIGH | PowerShell encoded command |
| HUNT-002 | CRITICAL | curl/wget piped to shell |
| HUNT-003 | CRITICAL | LSASS memory access |
| HUNT-004 | MEDIUM | Scheduled task creation |
| HUNT-005 | HIGH | PsExec / WMI lateral movement |
| HUNT-006 | HIGH | Process hollowing API calls |
| HUNT-007 | MEDIUM | DNS tunneling (long subdomain) |
| HUNT-008 | MEDIUM | Suspicious sudo escalation |
| HUNT-009 | HIGH | Tor exit node connections |
| HUNT-010 | MEDIUM | Data exfil via cloud storage |

## Install & Run on Kali

```bash
cd 03-advanced/99-threat-hunting-toolkit
pip install -e .
threat-hunting-toolkit hunt /var/log --exit-code -o report.json
threat-hunting-toolkit ioc-scan /var/log/auth.log --iocs iocs.jsonl
threat-hunting-toolkit list-rules
```

## Custom Rules

```json
{
  "rules": [
    {
      "rule_id": "CUSTOM-001",
      "name": "My Custom Rule",
      "severity": "HIGH",
      "mitre_technique": "T1059",
      "patterns": ["evil_pattern_1", "evil_pattern_2"],
      "condition": "any"
    }
  ]
}
```

## Testing

```bash
pytest tests/ -v --cov=project_99
```
