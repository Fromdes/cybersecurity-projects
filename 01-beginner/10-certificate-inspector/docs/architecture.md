# Architecture — Project 10: X.509 Certificate Inspector

## Certificate Loading

Two paths into the same `x509.Certificate` object:

```
File path   →  load_from_file()  →  try PEM → try DER → x509.Certificate
Host:port   →  load_from_host()  →  ssl.create_default_context() + socket → DER → x509.Certificate
```

`load_from_host` uses the OS trust store by default (`ssl.create_default_context()`),
so it validates the full chain. This means expired or self-signed certs on live hosts
will cause a connection error before we can inspect them — which is intentional
behaviour (fail-secure). For offline analysis, use `load_from_file` instead.

## Report Generation

`inspect_certificate()` produces an immutable `CertificateReport` (frozen dataclass)
containing all inspection results plus a `warnings` list. Callers can check
`len(report.warnings) == 0` for a clean bill of health.

## Extension Handling

The `SubjectAlternativeName` extension is optional. Code uses a `try/except
ExtensionNotFound` pattern rather than checking for the extension first, which is
idiomatic with the cryptography library.
