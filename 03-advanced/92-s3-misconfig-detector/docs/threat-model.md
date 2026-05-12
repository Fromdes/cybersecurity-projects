# Threat Model — S3 Misconfiguration Detector

## STRIDE Analysis

| Threat | Component | Mitigation |
|---|---|---|
| Information Disclosure | Public read buckets | S3-001 detects Principal:* GetObject |
| Tampering | Public write access | S3-002 detects Principal:* PutObject |
| Repudiation | ACL changes | S3-004 detects public ACL modification |
| Elevation of Privilege | Wildcard grants | S3-005 catches s3:* without conditions |

## Common Attack Scenarios

1. **Data breach via misconfigured bucket**: `s3:GetObject` with `Principal: *` exposes all objects
2. **Malware distribution**: Public `s3:PutObject` allows attacker to upload malicious content
3. **Bucket takeover**: `s3:PutBucketAcl` with `Principal: *` lets attackers lock out the owner
4. **Reconnaissance**: `s3:ListBucket` with `Principal: *` reveals internal object key names
