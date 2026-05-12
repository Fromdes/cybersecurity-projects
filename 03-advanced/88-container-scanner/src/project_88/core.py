"""Container Image Scanner — inspect Docker image tarballs for security issues."""

from __future__ import annotations

import hashlib
import json
import re
import tarfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator


@dataclass(frozen=True)
class ImageFinding:
    """A security finding in a container image."""

    rule_id: str
    severity: str
    title: str
    description: str
    layer: str = ""
    file_path: str = ""
    mitre_technique: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "layer": self.layer,
            "file_path": self.file_path,
            "mitre_technique": self.mitre_technique,
        }


# ── Sensitive file patterns ───────────────────────────────────────────────────

SENSITIVE_FILES: tuple[tuple[str, str, str], ...] = (
    (r"etc/shadow$", "CRITICAL", "Shadow password file exposed"),
    (r"etc/passwd$", "WARN", "Passwd file exposed in image"),
    (r"\.pem$|\.key$|\.p12$|\.pfx$", "CRITICAL", "Private key file in image layer"),
    (r"\.env$", "HIGH", "Environment file with potential secrets"),
    (r"id_rsa$|id_dsa$|id_ecdsa$|id_ed25519$", "CRITICAL", "SSH private key in image"),
    (r"\.aws/credentials$|aws_credentials", "CRITICAL", "AWS credentials file"),
    (r"\.kubeconfig$|kubeconfig$", "HIGH", "Kubernetes config in image"),
    (r"\.dockercfg$|config\.json$", "HIGH", "Docker registry credentials"),
    (r"\.git/config$", "WARN", "Git config with potential credentials"),
    (r"Dockerfile$", "INFO", "Dockerfile included in image"),
)

# ── Config checks ──────────────────────────────────────────────────────────────

def _check_image_config(config: dict[str, Any], image_name: str) -> list[ImageFinding]:
    """Check image config JSON for security issues."""
    findings: list[ImageFinding] = []
    cfg = config.get("config", config.get("Config", {}))

    # Check running as root
    user = cfg.get("User", "")
    if not user or user in ("root", "0", "0:0"):
        findings.append(ImageFinding(
            rule_id="IMG-001",
            severity="CRITICAL",
            title="Image configured to run as root",
            description="The image USER is unset or root. Add USER <nonroot> in Dockerfile.",
            mitre_technique="T1611",
        ))

    # Check for privileged env vars that might contain secrets
    env_list = cfg.get("Env", []) or []
    secret_env_re = re.compile(r"(?i)(password|secret|token|api_key|private_key)=\S+")
    for env_var in env_list:
        if secret_env_re.search(env_var):
            findings.append(ImageFinding(
                rule_id="IMG-002",
                severity="CRITICAL",
                title="Secret in image ENV variable",
                description=f"Potential secret in ENV: {env_var[:60]}",
                mitre_technique="T1552",
            ))

    # Check entrypoint/cmd for dangerous patterns
    for key in ("Entrypoint", "Cmd"):
        val = cfg.get(key) or []
        if isinstance(val, list):
            joined = " ".join(str(v) for v in val)
        else:
            joined = str(val)
        if re.search(r"\bsh\b|\bbash\b", joined) and re.search(r"-c\b", joined):
            findings.append(ImageFinding(
                rule_id="IMG-003",
                severity="WARN",
                title=f"Shell -c in {key}",
                description=f"{key} uses shell -c which can be hard to audit: {joined[:80]}",
            ))

    return findings


def _scan_tar_for_sensitive_files(tf: tarfile.TarFile, layer_name: str) -> list[ImageFinding]:
    """Scan a tar member list for sensitive filenames."""
    findings: list[ImageFinding] = []
    for member in tf.getmembers():
        path = member.name.lstrip("./")
        for pattern, severity, title in SENSITIVE_FILES:
            if re.search(pattern, path, re.IGNORECASE):
                findings.append(ImageFinding(
                    rule_id="IMG-004",
                    severity=severity,
                    title=title,
                    description=f"Sensitive file detected in image layer: {path}",
                    layer=layer_name,
                    file_path=path,
                    mitre_technique="T1552.001",
                ))
                break  # one finding per file
    return findings


def _read_layer_packages(tf: tarfile.TarFile) -> list[str]:
    """Extract installed package names from dpkg status or rpm db (heuristic)."""
    packages: list[str] = []
    for member in tf.getmembers():
        if member.name.endswith("var/lib/dpkg/status"):
            try:
                f = tf.extractfile(member)
                if f:
                    content = f.read().decode("utf-8", errors="replace")
                    packages.extend(re.findall(r"^Package:\s+(\S+)", content, re.MULTILINE))
            except Exception:
                pass
    return packages


# ── Image scanner ──────────────────────────────────────────────────────────────

@dataclass
class ScanResult:
    """Full scan result for a container image tarball."""

    image_path: str
    sha256: str
    findings: list[ImageFinding]
    layers: list[str]
    packages: list[str]

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        by_sev: dict[str, int] = {}
        for f in self.findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        return {
            "image_path": self.image_path,
            "sha256": self.sha256,
            "layer_count": len(self.layers),
            "package_count": len(self.packages),
            "total_findings": len(self.findings),
            "by_severity": by_sev,
            "findings": [f.to_dict() for f in self.findings],
        }


def scan_image_tarball(path: Path) -> ScanResult:
    """Scan a Docker image tarball (saved with docker save) for security issues."""
    sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
    findings: list[ImageFinding] = []
    layers: list[str] = []
    packages: list[str] = []

    with tarfile.open(path, "r:*") as outer:
        # Find and read manifest.json
        config_data: dict[str, Any] = {}
        try:
            manifest_member = outer.getmember("manifest.json")
            mf = outer.extractfile(manifest_member)
            if mf:
                manifests = json.loads(mf.read())
                if manifests and isinstance(manifests, list):
                    config_file = manifests[0].get("Config", "")
                    layers = manifests[0].get("Layers", [])
                    if config_file:
                        cfg_member = outer.getmember(config_file)
                        cf = outer.extractfile(cfg_member)
                        if cf:
                            config_data = json.loads(cf.read())
        except (KeyError, json.JSONDecodeError):
            pass

        if config_data:
            findings.extend(_check_image_config(config_data, path.name))

        # Scan each layer tarball
        for layer_path in layers:
            try:
                layer_member = outer.getmember(layer_path)
                layer_file = outer.extractfile(layer_member)
                if layer_file:
                    import io
                    layer_data = layer_file.read()
                    with tarfile.open(fileobj=io.BytesIO(layer_data), mode="r:*") as layer_tf:
                        findings.extend(_scan_tar_for_sensitive_files(layer_tf, layer_path))
                        packages.extend(_read_layer_packages(layer_tf))
            except (KeyError, tarfile.TarError):
                continue

    return ScanResult(
        image_path=str(path),
        sha256=sha256,
        findings=findings,
        layers=layers,
        packages=list(set(packages)),
    )


def create_mock_image_tarball(path: Path, config: dict[str, Any] | None = None) -> None:
    """Create a minimal mock Docker image tarball for testing."""
    import io
    import json

    if config is None:
        config = {"config": {"User": "", "Env": [], "Cmd": ["/bin/sh"]}}

    config_bytes = json.dumps(config).encode()
    config_sha = hashlib.sha256(config_bytes).hexdigest()
    config_name = f"{config_sha}.json"

    manifest = [{"Config": config_name, "Layers": [], "RepoTags": ["test:latest"]}]

    with tarfile.open(path, "w:gz") as outer:
        for name, data in (
            (config_name, config_bytes),
            ("manifest.json", json.dumps(manifest).encode()),
        ):
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            outer.addfile(info, io.BytesIO(data))
