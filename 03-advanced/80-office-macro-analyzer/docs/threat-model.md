# Threat Model — Office Macro Risk Analyzer

## MITRE Coverage
T1566.001, T1204.002, T1059.005, T1059.001, T1059.003, T1105, T1027, T1112, T1047, T1053

## Evasion Techniques
- Template injection: macros stored in remote template, not in document.
- XLM/Excel 4.0 macros: older format not covered by olevba VBA parser.
- Encrypted OLE2: password-protected documents prevent analysis.
