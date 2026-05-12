# Threat Model — Secrets Scanner

## MITRE Coverage
T1552, T1552.001, T1552.005

## Evasion Techniques
- String splitting: `"AKIA" + "IOSFODNN7EXAMPLE"` defeats single-line regex.
- Encoding: base64-encoded secrets.
- Environment variable indirection: the scanner only finds values written in files.

For comprehensive coverage, complement with git history scanning and SAST tools.
