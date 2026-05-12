# Architecture — S3 Misconfiguration Detector

## Components

```
cli.py         → Click interface (check command)
core.py        → Policy parser + check engine
  check_public_read()                 → stmt → S3Finding | None
  check_public_write()                → stmt → S3Finding | None
  check_public_list()                 → stmt → S3Finding | None
  check_public_acl_change()           → stmt → S3Finding | None
  check_wildcard_action_authenticated() → stmt → S3Finding | None
  analyze_bucket_policy()             → dict → BucketAnalysis
  analyze_policy_file()               → Path → BucketAnalysis
```

## Key Design Decisions

- **Condition-awareness**: Public-access findings are suppressed when a Condition block is present (common for IP/VPC-restricted access)
- **Deduplication**: Each rule_id fires at most once per policy regardless of how many statements match
- **Principal parsing**: Handles both string `"*"` and dict `{"AWS": [...]}` principal formats
