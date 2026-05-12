# Architecture — Terraform Security Scanner

## Components

```
cli.py         → Click interface (scan command)
core.py        → HCL parser + check engine
  parse_hcl_blocks()     → str → list[HCLBlock]
  check_*()              → HCLBlock → TFFinding | None
  scan_file()            → Path → list[TFFinding]
  scan_directory()       → Path → ScanReport
```

## HCL Parsing

Regex-based block detection without a full HCL parser:
1. Scan for `resource "type" "name" {` headers
2. Use brace-depth counting to extract block bodies
3. Apply per-check regex patterns against body text

This covers common patterns without requiring `pyhcl` or Terraform binary.
