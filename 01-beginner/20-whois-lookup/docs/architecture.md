# Architecture — Project 20: WHOIS Lookup Wrapper

## Module Layout
```
src/project_20/
  core.py   — WHOIS logic (WhoisResult, lookup, _parse, _str_or_empty, _first_date, _list_of_str)
  cli.py    — argparse CLI (human / --json output)
```

## Data Flow
```
User → CLI → lookup(query)
               └─ whois.whois(query)   [python-whois library]
               └─ _parse(query, data)
                    └─ _str_or_empty(data.registrar)
                    └─ _first_date(data.creation_date)   [handles list or datetime]
                    └─ _list_of_str(data.name_servers)
                  → WhoisResult(frozen dataclass)
             → _print_human() or json.dumps(_result_to_dict())
           → stdout
```

## Key Design Decisions
- `python-whois` returns inconsistent types (str|list|datetime|list[datetime]);
  helper functions normalize all fields before storing in the frozen dataclass
- `_first_date` takes the earliest date from a list (WHOIS can return multiple dates)
- Name servers are lowercased for consistent comparison
- `WhoisResult` is a frozen dataclass for safe passing across threads
