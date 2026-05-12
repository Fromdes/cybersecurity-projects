# Architecture — Project 33: Browser History Privacy Cleaner

## Database Schema (Chrome/Chromium)
```
urls table: id, url, title, visit_count, ...
visits table: id, url (FK→urls.id), visit_time (μs since 1601-01-01)
```

## Database Schema (Firefox)
```
moz_places table: id, url, title, visit_count, ...
moz_historyvisits table: id, place_id (FK), visit_date (μs since Unix epoch)
```

## Safe Read Pattern
```
Live DB (may be locked by browser)
    │
    └─ shutil.copy2 → /tmp/history_xxxxx.db
                           │
                           └─ sqlite3.connect → read-only query
                           └─ tmp_path.unlink() (always cleaned up)
```

## Data Flow
```
find_profiles()
    └─ iterates BROWSER_PATHS, checks for History / places.sqlite
    └─ returns {browser_name: [profile_path, ...]}

scan_profile(path, browser, patterns)
    └─ _read_{chrome,firefox}_history(path) → [HistoryEntry]
    └─ compiled regex filter → matched list
    └─ returns ScanResult(total, matched, entries)

delete_entries(path, browser, patterns)
    └─ opens live DB directly (must be closed)
    └─ fetches all (id, url) rows
    └─ finds IDs matching any pattern
    └─ DELETE visits WHERE url IN (ids)
    └─ DELETE urls WHERE id IN (ids)
    └─ VACUUM → reclaim space
    └─ returns count deleted
```
