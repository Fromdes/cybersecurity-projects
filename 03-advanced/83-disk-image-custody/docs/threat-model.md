# Threat Model — Disk Image Hash & Chain-of-Custody

## MITRE Coverage
T1070, T1565

## Known Weaknesses

- JSON custody file is not cryptographically signed in this implementation.
- Actor field is self-reported (getpass.getuser()); can be spoofed.
- For legal admissibility, store on write-once media and add HMAC or GPG signature.

## Production Hardening

1. Sign custody file with `gpg --sign` after each write.
2. Store on WORM storage or append-only filesystem.
3. Log to remote immutable audit log (syslog-ng / remote append-only S3).
