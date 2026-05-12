# Architecture — Supply Chain Verifier

## Components

```
cli.py         → Click interface (hash, verify, check-sums commands)
core.py        → Verification engine
  hash_artifact()           → Path → str
  verify_hash()             → Path, expected → bool
  parse_checksums_file()    → Path → list[ChecksumEntry]
  parse_slsa_attestation()  → dict → SLSAProvenance
  _infer_slsa_level()       → builder/fields → int
  verify_artifact()         → Path, options → VerificationResult
```

## SLSA Level Inference

| Level | Criteria |
|---|---|
| 0 | No builder ID |
| 1 | Builder ID present |
| 2 | Builder ID + invocation context |
| 3 | Hosted builder (GitHub/GitLab/GCP) + materials + invocation + SLSA v1 predicate |
