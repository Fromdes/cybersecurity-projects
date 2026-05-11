# Architecture — Project 17: TLS Handshake Inspector

## Module Layout
```
src/project_17/
  core.py   — TLS inspection (inspect_host, _parse_cert, CertInfo, TLSResult)
  cli.py    — argparse CLI (human / --json output modes)
```

## Data Flow
```
User → CLI → inspect_host(host, port)
               └─ ssl.create_default_context()
               └─ socket.create_connection(host, port, timeout=10)
               └─ ctx.wrap_socket(raw, server_hostname=host)
               └─ conn.cipher()     → (name, protocol, bits)
               └─ conn.version()    → protocol string
               └─ conn.getpeercert()→ raw cert dict
               └─ _parse_cert(raw)  → CertInfo
             → TLSResult
           → _print_human() or json.dumps(_result_to_dict())
           → stdout
```

## Key Design Decisions
- Uses stdlib `ssl` only — no sslyze/cryptography dependency
- `ssl.create_default_context()` validates the certificate chain by default
- `_parse_cert` handles missing fields gracefully (defaults to epoch datetime)
- JSON output serializes datetime as ISO 8601 strings
