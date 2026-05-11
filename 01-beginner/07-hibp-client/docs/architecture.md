# Architecture — Project 07: Have-I-Been-Pwned Client

## k-Anonymity Protocol

```
1. Hash password with SHA-1:  SHA1("password") = "5BAA61E4..."
2. Take prefix (5 chars):     prefix = "5BAA6"
3. GET /range/5BAA6           → server returns all hashes starting with 5BAA6
4. Find our suffix locally:   "1E4C9B93..." in response? → breach count
```

The HIBP server sees thousands of requests for prefix "5BAA6" and cannot tell
which specific password any individual user was checking.

## Dependency Injection for Testing

`check_password()` and `check_hash()` accept an optional `requests.Session`
parameter. Tests pass a `MagicMock` session with pre-loaded fake responses —
no real HTTP traffic during unit tests.
