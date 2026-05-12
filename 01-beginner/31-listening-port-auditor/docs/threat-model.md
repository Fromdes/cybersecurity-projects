# Threat Model — Project 31: Listening Port Auditor

## Assets
- Inventory of listening network services on the host
- Process-to-port attribution data

## Threat Actors
- Adversary who has code execution and opens a backdoor listener
- Insider threat installing unauthorized services
- Misconfigured software accidentally binding to dangerous ports

## STRIDE Analysis
| Threat | Example | Mitigation |
|---|---|---|
| Spoofing | Malware impersonates sshd on port 22 | Compare process executable path, not just name |
| Tampering | Attacker kills auditor and opens backdoor | Run auditor as a systemd service with auto-restart |
| Info Disclosure | Database port exposed to 0.0.0.0 | Flag world-bound database/cache ports as HIGH |
| Repudiation | Backdoor deleted before audit runs | Store periodic snapshots; diff against baseline |
| Elevation of Privilege | Non-root process on privileged port via CAP_NET_BIND | Check process UID vs port number |

## Threat Hunting Use Cases
- Alert when a new port appears that was not in the previous snapshot
- Alert on any world-bound (0.0.0.0) port that is not in an approved allowlist
- Alert when a process name on a well-known port doesn't match the expected binary
- Detect ephemeral high-number TCP listeners that could be C2 callbacks
