# Architecture — Cloud IAM Policy Analyzer

## Components

```
cli.py          → Click interface (analyze command)
core.py         → Policy parser + rule engine
  analyze_statement()    → dict → list[IAMFinding]
  analyze_policy_dict()  → dict → PolicyAnalysis
  analyze_policy_file()  → Path → PolicyAnalysis
```

## Rule Logic

Each statement is checked independently. Rules use set intersection between
the statement's Action list and pre-defined dangerous action sets. Resource
scope is also considered — a broad read action is only flagged as data exfil
risk when paired with a wildcard resource.
