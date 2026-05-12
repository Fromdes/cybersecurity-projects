# Threat Model — Project 33: Browser History Privacy Cleaner

## Assets
- Local browser history SQLite databases (Chrome: History, Firefox: places.sqlite)
- Visit timestamps, search queries, credentials-page URLs

## Threat Actors
- Attacker with local file system access (compromised account, physical access)
- Malware scanning user profile directories for SQLite databases
- Forensic investigator on a shared machine

## STRIDE Analysis
| Threat | Example | Mitigation |
|---|---|---|
| Info Disclosure | Malware reads History database and exfiltrates URLs | Clean tracker/sensitive entries; encrypt history (browser setting) |
| Tampering | Attacker writes fake history entries to frame user | Hash baseline of history file; detect modifications |
| Repudiation | User denies visiting a URL; history contradicts | Implement scan-before-clean to document what was present |
| Denial of Service | Malformed DELETE corrupts SQLite database | Write to temp copy in scan mode; VACUUM after delete |

## Threat Hunting Use Cases
- Scan for C2 URLs in browser history after incident response
- Detect if history contains credential-phishing URLs (e.g., bank login + redirect)
- Find evidence of internal data exfiltration via web uploads
- Use history timestamps to reconstruct attacker browser-based reconnaissance
