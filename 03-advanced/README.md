# Level 3 — Advanced Projects (76–100)

These 25 projects build production-grade security systems: a SIEM, EDR agent, forensics toolkit, cloud security scanners, and ML-based anomaly detection. Several are multi-component and run as persistent services.

**Skills you'll build**: real-time event correlation, endpoint detection, memory forensics, static malware analysis, DevSecOps (SBOM, container scanning, K8s RBAC, Terraform), cloud IAM analysis, zero-trust architecture, DLP, double-ratchet encryption, and compliance auditing (GDPR/KVKK).

---

## Projects

| # | Name | MITRE ATT&CK | Status |
|---|------|-------------|--------|
| [76](76-mini-siem-platform/) | Mini SIEM Platform | T1190, T1071 | Pending |
| [77](77-lightweight-edr-agent/) | Lightweight EDR Agent | T1059 | Pending |
| [78](78-real-time-fim/) | Real-Time FIM (inotify) | T1565 | Pending |
| [79](79-static-malware-analyzer/) | Static Malware Analyzer | T1204 | Pending |
| [80](80-office-macro-analyzer/) | Office Macro Risk Analyzer | T1204.002 | Pending |
| [81](81-forensics-timeline-builder/) | Forensics Timeline Builder | T1070 | Pending |
| [82](82-memory-dump-ioc-extractor/) | Memory Dump IOC Extractor | T1055 | Pending |
| [83](83-disk-image-hash-custody/) | Disk Image Hash & Chain-of-Custody | T1565 | Pending |
| [84](84-secrets-scanner/) | Secrets Scanner | T1552 | Pending |
| [85](85-dependency-vulnerability-checker/) | Dependency Vulnerability Checker | T1195.001 | Pending |
| [86](86-sbom-generator/) | SBOM Generator | T1195 | Pending |
| [87](87-dockerfile-linter/) | Dockerfile Linter & CIS Checker | T1610 | Pending |
| [88](88-container-image-scanner/) | Container Image Scanner | T1610 | Pending |
| [89](89-kubernetes-rbac-auditor/) | Kubernetes RBAC Auditor | T1078.004 | Pending |
| [90](90-terraform-security-scanner/) | Terraform Security Scanner | T1578 | Pending |
| [91](91-cloud-iam-analyzer/) | Cloud IAM Policy Analyzer | T1078.004 | Pending |
| [92](92-s3-misconfiguration-detector/) | S3 Misconfiguration Detector | T1530 | Pending |
| [93](93-zero-trust-gateway/) | Zero Trust Network Gateway | T1078 | Pending |
| [94](94-supply-chain-verifier/) | Supply Chain Verifier (SLSA/Sigstore) | T1195 | Pending |
| [95](95-dlp-engine/) | DLP Engine | T1048 | Pending |
| [96](96-behavioral-auth-poc/) | Behavioral Authentication PoC | T1078 | Pending |
| [97](97-encrypted-messaging-library/) | Encrypted Messaging Library (Double Ratchet) | T1040 | Pending |
| [98](98-network-ml-anomaly-detector/) | Network ML Anomaly Detector | T1071 | Pending |
| [99](99-threat-hunting-toolkit/) | Threat Hunting Toolkit | T1071, T1190 | Pending |
| [100](100-gdpr-kvkk-compliance-auditor/) | GDPR/KVKK Compliance Auditor | T1530, T1078 | Pending |

---

## Prerequisites

Complete Levels 1 and 2 first. Some projects require additional system packages:

```bash
sudo apt install -y volatility3 inotify-tools docker.io
pip install boto3 scikit-learn fastapi pandas
```

Several advanced projects may require root privileges or a dedicated VM — see each project's README for the `Privileges` section.
