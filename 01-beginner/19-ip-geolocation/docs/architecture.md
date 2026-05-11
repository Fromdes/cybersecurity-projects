# Architecture — Project 19: IP Geolocation & ASN Lookup

## Module Layout
```
src/project_19/
  core.py   — geo logic (GeoResult, lookup_ip, _validate_ip, _parse_result)
  cli.py    — argparse CLI (single IP / --file bulk / --json output)
```

## Data Flow
```
User → CLI → lookup_ip(ip)
               └─ _validate_ip(ip)  [raises ValueError if invalid]
               └─ requests.get(https://ip-api.com/json/{ip}, fields=..., timeout=10)
               └─ response.raise_for_status()
               └─ _parse_result(data) → GeoResult
             → _print_human() or json.dumps(dataclasses.asdict(result))
           → stdout

         --file path → _process_file() → [lookup_ip(ip) for ip in ips]
```

## Key Design Decisions
- ip-api.com free tier (HTTPS, no key needed) used for zero-config operation
- `CALLER_SENTINEL = "me"` skips validation for caller's own IP lookup
- `_parse_result` uses `str()` casts to handle API inconsistencies
- Bulk file mode continues on errors (prints error, sets non-zero exit code)
- `dataclasses.asdict()` for JSON serialisation (no custom encoder needed)
