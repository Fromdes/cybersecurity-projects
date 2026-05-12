# Threat Model — Kubernetes RBAC Auditor

## STRIDE Analysis

| Threat | Component | Mitigation |
|---|---|---|
| Spoofing | YAML parser | PyYAML safe_load_all (no arbitrary object deserialization) |
| Tampering | RBAC manifests | Audit in CI before applying to cluster |
| Repudiation | Findings | JSON report with source path and resource names |
| Information Disclosure | Report JSON | Store reports in access-controlled artifact store |
| Denial of Service | Large YAML files | Streaming multi-doc parser; no full file load into RAM |
| Elevation of Privilege | Detected rules | RBAC-001–010 cover all known K8s escalation paths |

## Attack Scenarios Detected

1. **Cluster-admin via wildcard**: `resources: ["*"], verbs: ["*"]` — RBAC-001
2. **Secret exfiltration**: Read access to `secrets` lets attacker harvest credentials — RBAC-004
3. **Container escape via pod exec**: `pods/exec` + create/get allows shell into any container — RBAC-003
4. **RBAC self-escalation**: `bind` / `escalate` on role resources lets attacker grant themselves any permission — RBAC-005
5. **Kubelet API access via node proxy**: Can bypass API server auth for node-level operations — RBAC-006
