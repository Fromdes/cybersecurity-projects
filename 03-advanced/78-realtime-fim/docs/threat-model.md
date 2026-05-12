# Threat Model — Real-Time FIM

## Assets
- Monitored file system paths
- Baseline JSON file (integrity critical)
- FIM event log

## MITRE Coverage
T1070, T1556, T1547, T1525, T1485

## Limitations
- watchdog is user-space; a kernel rootkit can bypass it.
- SHA-256 collision is computationally infeasible today but monitor algorithm agility.
- High I/O systems may produce event storms — add debouncing for production use.
