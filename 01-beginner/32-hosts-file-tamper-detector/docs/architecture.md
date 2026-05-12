# Architecture — Project 32: Hosts File Tamper Detector

## Component Overview
```
┌─────────────────────────────────────────────────────┐
│  CLI (cli.py)                                       │
│   ├─ baseline → save_baseline()                     │
│   ├─ check   → load_baseline() + detect_tampering() │
│   └─ show    → parse_hosts()                        │
└───────────────────────┬─────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────┐
│  Core (core.py)                                     │
│   ├─ parse_hosts(path) → [HostsEntry]               │
│   │    └─ regex-based line parsing, skip comments   │
│   ├─ hash_file(path) → str  (SHA-256 hex)           │
│   ├─ save_baseline(hosts, out) → dict (JSON)        │
│   ├─ load_baseline(path) → dict                     │
│   └─ detect_tampering(baseline, path) → TamperResult│
│        ├─ set-diff: added / removed entries         │
│        └─ _is_suspicious_redirect(ip, hostname)     │
└─────────────────────────────────────────────────────┘
```

## Baseline File Format (JSON)
```json
{
  "hash": "<sha256hex>",
  "entries": [
    {"ip": "127.0.0.1", "hostname": "localhost", "aliases": []},
    ...
  ]
}
```

## Detection Logic
1. Re-hash the live file; compare to baseline hash → any byte change detected
2. Re-parse entries; set-diff against baseline entries
3. For each added (ip, hostname) pair: call `_is_suspicious_redirect`
   - Suspicious = external IP (not 127.x or 0.0.0.0) mapping a high-value domain
4. `is_tampered = hash_changed OR suspicious_redirects_present`
5. CLI exits with code 2 if tampered (pipeline-friendly)
