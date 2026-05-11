# Architecture — Project 18: DNS Lookup & Reverse DNS Tool

## Module Layout
```
src/project_18/
  core.py   — DNS logic (RecordType, DNSRecord, lookup, reverse_lookup)
  cli.py    — argparse CLI (lookup / reverse subcommands)
```

## Data Flow
```
User → CLI → lookup(hostname, RecordType)
               └─ dns.resolver.Resolver(timeout=N)
               └─ resolver.resolve(hostname, "A")
               └─ [DNSRecord(name, type, ttl, value), ...]
             → stdout (tabular)

         reverse_lookup(ip)
               └─ dns.reversename.from_address(ip) → "x.x.x.x.in-addr.arpa."
               └─ resolver.resolve(ptr_name, "PTR")
               └─ [DNSRecord(ptr_name, PTR, ttl, hostname), ...]
             → stdout
```

## Key Design Decisions
- `dnspython` used instead of stdlib `socket.getaddrinfo` for full record type support
- `NXDOMAIN` and `NoAnswer` are mapped to `DNSException` for uniform error handling
- `_make_resolver()` sets both `timeout` and `lifetime` to prevent hangs
- `_rdata_str()` wrapper makes rdata serialization mockable in tests
