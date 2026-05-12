# Architecture — DLP Engine

## Components

```
cli.py         → Click interface (scan, redact commands)
core.py        → Rule engine + scanner + redactor
  DLPRule              → Frozen dataclass: id, pattern, category, severity
  DEFAULT_RULES        → 15 pre-built rules
  scan_text()          → str → list[DLPFinding]
  scan_file()          → Path → list[DLPFinding]
  scan_directory()     → Path → DLPReport
  redact_text()        → str → str (all matches replaced)
```

## Rule Matching

Each rule compiles a regex at module load time. `scan_text()` iterates all rules,
collecting `re.findall()` matches with positional info for line/column reporting.
Binary-extension files are skipped before attempting to decode.

## Redaction

`redact_text()` applies all rules' patterns sequentially via `re.sub()`, replacing
each match with the rule's `redact_with` marker (default: `[REDACTED]`).
