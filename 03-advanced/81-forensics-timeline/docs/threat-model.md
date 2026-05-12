# Threat Model — Forensics Timeline Builder

## MITRE Coverage
T1070.006, T1005, T1021, T1059

## Limitations
- Filesystem timestamps are easily modified by an attacker (timestomping).
- Journal/changelog-based timestamps (ext4 journal, ntfs logfile) are not yet parsed.
- Log files themselves may have been cleared or tampered with.

Combine with immutable logging (e.g., remote syslog) for reliable forensic evidence.
