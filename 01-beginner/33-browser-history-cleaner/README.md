# Project 33 - Browser History Privacy Cleaner
> Scan Chrome, Chromium, and Firefox history databases for tracker URLs and selectively delete matching entries to reduce local data exposure.

## What Attack Does This Defend Against? (MITRE ATT&CK IDs)
| Technique | ID | Description |
|---|---|---|
| Data from Local System | T1005 | Attackers read browser SQLite databases to steal history |
| Credentials from Web Browsers | T1555.003 | History reveals credential-entry sites visited |
| Browser Session Hijacking | T1185 | History helps attackers reconstruct browsing sessions |
| Indicator Removal | T1070 | Privacy cleaning removes traces of sensitive activity |

## Features
- **Auto-discovery**: finds Chrome, Chromium, and Firefox profiles on Linux
- **Scan mode**: preview matched entries before deletion (dry run)
- **Clean mode**: surgically removes matching rows from SQLite (browser must be closed)
- **Pattern engine**: built-in tracker patterns (Google, Bing, doubleclick, analytics) plus custom `--pattern` flags
- **Safe read**: scan uses a temp-file copy of the database, never touches live data

## Tech Stack
- Python 3.11+ (stdlib: `sqlite3`, `re`, `shutil`, `tempfile`, `pathlib`)

## Architecture
```
CLI (cli.py): scan | clean
  find_profiles() → {browser: [Path]}
  scan_profile(path, browser, patterns) → ScanResult
    └─ _read_chrome_history(path) OR _read_firefox_history(path)
    └─ regex filter → matched entries
  delete_entries(path, browser, patterns) → int
    └─ _delete_chrome_entries() OR _delete_firefox_entries()
```

## Threat Model (STRIDE)
| Category | Threat | Mitigation |
|---|---|---|
| Info Disclosure | Attacker reads history SQLite | Clean/encrypt sensitive entries |
| Tampering | Tool deletes wrong entries | Scan mode for preview; patterns are explicit |
| Repudiation | No confirmation before deletion | Always scan first; clean requires explicit subcommand |
| Denial of Service | Deleting wrong entries breaks browser | VACUUM after delete; copies for safe reads |

## Install & Run on Kali
```bash
cd 01-beginner/33-browser-history-cleaner
pip install -e .
history-cleaner scan
history-cleaner scan --browser firefox
history-cleaner scan --pattern "my-sensitive-domain\.com"
history-cleaner clean   # close browser first!
```

## Privileges
No root needed. Runs as the current user.

## Example Output
```
[chrome] /home/user/.config/google-chrome/Default
  Total entries : 1423
  Matched       : 87
    2024-01-15 https://google.com/search?q=bank+account
    2024-01-15 https://doubleclick.net/tracker/...
    ... and 67 more

Total matched entries: 87
```

## Testing
```bash
pytest --cov=project_33 --cov-report=term-missing
```

## What You'll Learn
- Browser history is stored in SQLite — readable by any process with filesystem access
- Chrome's time format (microseconds since 1601-01-01) vs Unix epoch
- How to safely read a locked SQLite database using file copy
- MITRE T1555.003 credential theft via browser databases

## References
- [MITRE ATT&CK T1005 – Data from Local System](https://attack.mitre.org/techniques/T1005/)
- [MITRE ATT&CK T1555.003 – Credentials from Web Browsers](https://attack.mitre.org/techniques/T1555/003/)
- [Chrome History SQLite schema](https://forensicswiki.xyz/wiki/index.php?title=Google_Chrome)
