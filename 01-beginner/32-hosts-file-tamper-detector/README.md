# Project 32 - Hosts File Tamper Detector
> Snapshot /etc/hosts as a cryptographic baseline and alert when entries are added, removed, or redirected to suspicious IPs — a classic DNS hijacking indicator.

## What Attack Does This Defend Against? (MITRE ATT&CK IDs)
| Technique | ID | Description |
|---|---|---|
| Modify Hosts File | T1565.001 | Adversaries add fake entries to redirect traffic |
| DNS Hijacking | T1071.004 | Hosts file overrides DNS to redirect to attacker IPs |
| Credential Access via Phishing | T1056 | Redirected banking/auth sites steal passwords |
| Persistence via Host File | T1564 | Malware adds its C2 to hosts to survive DNS blacklisting |

## Features
- **Baseline command**: SHA-256 hash + structured JSON snapshot of all entries
- **Check command**: diff current file vs baseline; exits 2 if tampered
- **Show command**: human-readable display of all active host mappings
- **Suspicious redirect detection**: flags when well-known domains (paypal.com, github.com …) are mapped to non-loopback IPs
- **No dependencies**: pure stdlib — nothing to install

## Tech Stack
- Python 3.11+ (stdlib only: `hashlib`, `json`, `re`, `pathlib`)

## Architecture
```
CLI (cli.py): baseline | check | show
  save_baseline(hosts, baseline_path) → dict
  load_baseline(baseline_path) → dict
  detect_tampering(baseline, hosts) → TamperResult
    └─ parse_hosts(path) → [HostsEntry]
    └─ hash_file(path) → str
    └─ _is_suspicious_redirect(ip, hostname) → bool
```

## Threat Model (STRIDE)
| Category | Threat | Mitigation |
|---|---|---|
| Tampering | Malware adds entries to hosts file | SHA-256 hash detects any byte change |
| Spoofing | High-value domain mapped to attacker IP | Suspicious redirect heuristic |
| Elevation of Privilege | Root-only edit highlights attacker foothold | Monitor file owner/permissions |
| Repudiation | Attacker removes tampered entries before audit | Baseline timestamp shows when change window opened |

## Install & Run on Kali
```bash
cd 01-beginner/32-hosts-file-tamper-detector
pip install -e .
sudo hosts-tamper-detect baseline
hosts-tamper-detect check
hosts-tamper-detect show
```

## Privileges
Root needed only to save baseline from /etc/hosts (read is world-readable). Check and show need no root.

## Example Output
```
Status       : TAMPERED
Hash changed : YES
Added entries:
  + 1.2.3.4 → paypal.com
SUSPICIOUS redirects detected:
  ! 1.2.3.4 → paypal.com (high-value target redirected)
```

## Testing
```bash
pytest --cov=project_32 --cov-report=term-missing
```

## What You'll Learn
- Why /etc/hosts modifications are a stealthy attack vector
- SHA-256 file integrity checking without third-party tools
- JSON baseline pattern for before/after comparison
- MITRE T1565.001 and DNS-level phishing detection

## References
- [MITRE ATT&CK T1565.001 – Stored Data Manipulation](https://attack.mitre.org/techniques/T1565/001/)
- [MITRE ATT&CK T1071.004 – DNS](https://attack.mitre.org/techniques/T1071/004/)
- [hosts(5) man page](https://man7.org/linux/man-pages/man5/hosts.5.html)
