# Threat Model — Lightweight EDR Agent

## MITRE ATT&CK Coverage

| Technique | ID |
|---|---|
| Command and Scripting Interpreter | T1059 |
| Abuse Elevation Control Mechanism: Sudo | T1548.003 |
| Application Layer Protocol | T1071 |
| System Network Connections Discovery | T1049 |
| Process Injection | T1055 |

## Limitations

- Cmdline-based detection can be evaded by obfuscation.
- Hidden process detection is heuristic; legitimate daemons may trigger it.
- No kernel-level hooks — user-space only.
