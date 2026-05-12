# Architecture — Project 31: Listening Port Auditor

## Component Overview
```
┌──────────────────────────────────────────────────────┐
│  CLI (cli.py)                                        │
│   ├─ argparse: --protocol, --min-risk, --json        │
│   └─ calls core functions, formats output            │
└────────────────────┬─────────────────────────────────┘
                     │
┌────────────────────▼─────────────────────────────────┐
│  Core (core.py)                                      │
│   ├─ list_listening_ports(protocol) → [PortEntry]    │
│   │    ├─ psutil.net_connections(kind)               │
│   │    ├─ _build_entry(conn, proto) → PortEntry      │
│   │    │    └─ psutil.Process(pid) for attribution   │
│   │    │    └─ _compute_risk() → (score, flags)      │
│   │    └─ deduplication + sort by risk               │
│   └─ filter_by_risk([PortEntry], min_level)          │
└──────────────────────────────────────────────────────┘
```

## Data Flow
1. `psutil.net_connections()` returns raw socket records
2. TCP sockets are filtered to `LISTEN` status only
3. Each socket is enriched with process name + username via `psutil.Process`
4. Risk score computed from: bind address, port number, port category, PID presence
5. Entries deduplicated (same port+protocol), sorted by score descending
6. CLI applies `filter_by_risk` then renders as table or JSON

## Risk Scoring Model
| Condition | Points |
|---|---|
| Bound to all interfaces (0.0.0.0 or ::) | +30 |
| Port is in DANGEROUS_PORTS set | +50 |
| Port 23 (telnet) | +60 additional |
| No owning PID found | +40 |
| TCP server on ephemeral port (≥49152) | +20 |
