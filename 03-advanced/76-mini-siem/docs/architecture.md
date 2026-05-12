# Architecture — Mini SIEM Platform

## Components

- **LogParser**: Converts raw log lines into normalized `LogEvent` objects.
- **SIEMEngine**: Correlates events against `DetectionRule` list; emits `Alert` objects.
- **AlertStore**: Thread-safe list; optional JSONL file persistence.
- **CLI**: `ingest` (batch), `tail` (real-time), `rules`, `summary`.

## Data Flow

```
Raw log line
    │
    ▼
LogParser.parse_line()
    │
    ▼
LogEvent (frozen dataclass)
    │
    ▼
SIEMEngine.process_event()
    │ for each DetectionRule
    ├── rule.matches(event) ── True ──► Alert created ──► AlertStore + callbacks
    └── False ──► skip
```

## Extension Points

- Add new `DetectionRule` objects to `BUILTIN_RULES` or pass a custom list.
- Subclass `LogParser` and register in `_PARSERS`.
- Add alert callbacks for webhook/email integration.
