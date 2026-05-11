# Architecture — Project 03: File Integrity Verifier

## Data Flow

```
fim init <dir>
    └─► create_baseline(dir)  ──►  {rel_path: sha256, ...}
              └─► save_baseline()  ──►  baseline.json

fim check <dir> --baseline baseline.json
    ├─► load_baseline()       ──►  {rel_path: sha256, ...}  (previous)
    ├─► create_baseline(dir)  ──►  {rel_path: sha256, ...}  (current)
    └─► check_integrity()     ──►  IntegrityReport
              └─► cli formats & prints
```

## IntegrityReport

Frozen dataclass — immutable after construction. Contains three lists:
- `new_files`: paths present now but absent from baseline
- `deleted_files`: paths in baseline but absent now  
- `modified_files`: paths present in both but with different hashes

## Security Notes

- The baseline JSON itself should be stored on read-only media or signed with
  Project 09 (RSA signatures) to prevent an attacker from updating it after
  modifying files.
- SHA-256 provides collision resistance; MD5/SHA-1 do not and should not be
  used for integrity monitoring.
