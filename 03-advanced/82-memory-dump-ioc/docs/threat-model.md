# Threat Model — Memory Dump IOC Extractor

## MITRE Coverage
T1071, T1070, T1041, T1055

## Limitations

- Regex extraction has high false-positive rates for short patterns (MD5).
- Encrypted/compressed memory regions yield no readable IOCs.
- For deep analysis use Volatility3 plugins on top of this tool's output.
