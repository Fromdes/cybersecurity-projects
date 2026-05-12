# Architecture — Threat Hunting Toolkit

## Components

```
cli.py         → Click interface (hunt, ioc-scan, list-rules)
core.py        → Rule engine + IOC matcher + hunt report
  HuntRule              → Frozen dataclass with patterns + condition
    .matches_line()     → str → bool (regex match)
    .matches_record()   → dict → bool (structured record)
  BUILTIN_RULES         → 10 pre-built MITRE-mapped rules
  hunt_file()           → Path → list[HuntMatch]
  hunt_directory()      → Path → HuntReport
  hunt_iocs_in_text()   → text + IOC list → matches
  load_rules_file()     → Path → list[HuntRule]
```

## Rule Matching Logic

- `condition: "any"` (default) — match if ANY pattern matches the line
- `condition: "all"` — match only if ALL patterns match (AND logic)
- `field_patterns` — match against structured JSON log fields specifically
