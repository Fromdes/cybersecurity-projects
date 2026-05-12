# Architecture — Dependency Vulnerability Checker

## Manifest Parsers

| File | Parser | Ecosystem |
|---|---|---|
| requirements.txt | `parse_requirements_txt()` | PyPI |
| package.json | `parse_package_json()` | npm |
| go.mod | `parse_go_mod()` | Go |

`detect_and_parse()` selects the correct parser by filename.

## OSV API

- Single query: `POST https://api.osv.dev/v1/query` — one package per request.
- Batch query: `POST https://api.osv.dev/v1/querybatch` — up to 100 packages per request.

The batch endpoint is used by default for efficiency. Rate limiting is handled gracefully.

## Severity Extraction

OSV responses include `database_specific.severity` (human label) and `severity[].score` (CVSS vector). Both are parsed; the human label takes precedence for display.
