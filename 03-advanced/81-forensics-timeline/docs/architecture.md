# Architecture — Forensics Timeline Builder

## Sources

| Source | Function | Format |
|---|---|---|
| Filesystem | `collect_filesystem_events()` | os.stat mtime/atime/ctime |
| Syslog | `collect_syslog_events()` | BSD syslog format |
| Generic | `collect_generic_log_events()` | ISO8601 timestamps |

## ForensicsTimeline

- Stores `TimelineEvent` frozen dataclasses.
- `sorted_events()` returns copy sorted by timestamp, with optional filters.
- `to_jsonl()` / `to_csv()` export for downstream tools.
