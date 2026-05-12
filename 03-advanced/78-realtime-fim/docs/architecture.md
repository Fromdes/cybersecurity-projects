# Architecture — Real-Time FIM

## Baseline Phase
- `Baseline.build()` walks directory trees, computes SHA-256, stores `FileRecord` frozen dataclasses.
- `Baseline.save()` persists to JSON; `Baseline.load()` restores.

## Verification Phase
- `Baseline.verify()` iterates all records: checks existence, recomputes hash, emits `FIMEvent`.

## Real-Time Phase
- `FIMWatcher` wraps watchdog `Observer` with `_FIMEventHandler`.
- On any filesystem event: computes new hash, emits `FIMEvent` via callback.
- `FIMEventLog` records events thread-safely; optionally persists JSONL.
