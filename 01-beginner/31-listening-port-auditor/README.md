# Project 31 - Listening Port Auditor
> Enumerate every open listening port on the host, identify its owning process, and risk-score it so defenders can spot unexpected services instantly.

## What Attack Does This Defend Against? (MITRE ATT&CK IDs)
| Technique | ID | Description |
|---|---|---|
| System Network Connections Discovery | T1049 | Adversaries enumerate network connections to map attack surface |
| Application Layer Protocol | T1071 | Malware opens listening ports for C2 communication |
| Remote Services | T1021 | Unexpected RDP/SSH listeners indicate lateral movement |
| Non-Standard Port | T1571 | Backdoors listen on unusual ports to avoid detection |

## Features
- **TCP & UDP enumeration**: covers both listening TCP sockets and bound UDP sockets
- **Process attribution**: maps each port to its owning PID, process name, and user
- **Risk scoring**: flags world-bound sockets (0.0.0.0), dangerous service ports (telnet, RDP, Redis), orphan ports with no owning process
- **Risk-level filter**: show only HIGH or MEDIUM risk findings
- **JSON output**: machine-readable for SIEM/SOC pipelines

## Tech Stack
- Python 3.11+, `psutil>=5.9`

## Architecture
```
CLI (cli.py)
  list_listening_ports(protocol) → [PortEntry]
    └─ psutil.net_connections()
    └─ _build_entry() → _compute_risk() → PortEntry
  filter_by_risk([PortEntry], min_level) → [PortEntry]
```

## Threat Model (STRIDE)
| Category | Threat | Mitigation |
|---|---|---|
| Tampering | Backdoor opens listening port | Baseline + alert on new HIGH-risk ports |
| Info Disclosure | Service exposes sensitive data | Flag world-bound database ports |
| Elevation of Privilege | Privileged process on unexpected port | Cross-check username vs. port |
| Repudiation | Attacker kills auditor process | Run auditor as separate privileged service |

## Install & Run on Kali
```bash
cd 01-beginner/31-listening-port-auditor
pip install -e .
sudo port-auditor
sudo port-auditor --protocol tcp --min-risk HIGH
sudo port-auditor --json
```

## Privileges
Root (sudo) recommended for full process attribution. Runs without root but PIDs may be missing.

## Example Output
```
PORT     PROTO ADDRESS              PROCESS              RISK    FLAGS
------------------------------------------------------------------------------------------
6379     tcp   0.0.0.0              redis-server         HIGH    port 6379 is high-risk; bound to all interfaces
3389     tcp   0.0.0.0              xrdp                 HIGH    port 3389 is high-risk; bound to all interfaces
22       tcp   0.0.0.0              sshd                 MEDIUM  bound to all interfaces
```

## Testing
```bash
pip install -r requirements.txt
pytest --cov=project_31 --cov-report=term-missing
```

## What You'll Learn
- `psutil.net_connections()` to enumerate sockets programmatically
- Difference between `LISTEN` (TCP) and bound UDP sockets
- Why world-bound listeners (0.0.0.0) are a higher risk than loopback-only
- MITRE T1049 / T1571 detection patterns

## References
- [MITRE ATT&CK T1049 – System Network Connections Discovery](https://attack.mitre.org/techniques/T1049/)
- [MITRE ATT&CK T1571 – Non-Standard Port](https://attack.mitre.org/techniques/T1571/)
- [psutil documentation](https://psutil.readthedocs.io/)
