"""SBOM Generator — produces CycloneDX-compatible Software Bill of Materials."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SBOM_SPEC_VERSION = "1.4"
SBOM_FORMAT = "CycloneDX"


@dataclass(frozen=True)
class Component:
    """A software component in the SBOM."""

    name: str
    version: str
    purl: str
    ecosystem: str
    licenses: list[str] = field(default_factory=list)
    hashes: dict[str, str] = field(default_factory=dict)
    description: str = ""

    def to_cyclonedx(self) -> dict[str, Any]:
        """Serialize as CycloneDX component dict."""
        comp: dict[str, Any] = {
            "type": "library",
            "bom-ref": f"{self.name}@{self.version}",
            "name": self.name,
            "version": self.version,
            "purl": self.purl,
        }
        if self.licenses:
            comp["licenses"] = [{"license": {"id": lic}} for lic in self.licenses]
        if self.hashes:
            comp["hashes"] = [{"alg": alg, "content": val} for alg, val in self.hashes.items()]
        if self.description:
            comp["description"] = self.description
        return comp

    def to_spdx(self) -> dict[str, Any]:
        """Serialize as SPDX package dict."""
        return {
            "SPDXID": f"SPDXRef-{self.name}-{self.version}".replace(".", "-"),
            "name": self.name,
            "versionInfo": self.version,
            "downloadLocation": self.purl,
            "filesAnalyzed": False,
            "licenseConcluded": self.licenses[0] if self.licenses else "NOASSERTION",
            "licenseDeclared": self.licenses[0] if self.licenses else "NOASSERTION",
            "copyrightText": "NOASSERTION",
        }


def _make_purl(ecosystem: str, name: str, version: str) -> str:
    """Build a Package URL (purl) string."""
    eco_map = {"PyPI": "pypi", "npm": "npm", "Go": "golang", "Maven": "maven"}
    purl_type = eco_map.get(ecosystem, ecosystem.lower())
    return f"pkg:{purl_type}/{name}@{version}"


# ── Manifest parsers ───────────────────────────────────────────────────────────

def parse_requirements_txt(path: Path) -> list[Component]:
    """Parse Python requirements.txt into components."""
    components: list[Component] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-")):
            continue
        m = re.match(r"^([A-Za-z0-9_\-\.]+)\s*(?:==|>=|~=|<=)\s*([A-Za-z0-9._\-]+)", line)
        if m:
            name, version = m.group(1), m.group(2)
            components.append(Component(
                name=name,
                version=version,
                purl=_make_purl("PyPI", name.lower(), version),
                ecosystem="PyPI",
            ))
    return components


def parse_package_json(path: Path) -> list[Component]:
    """Parse Node.js package.json into components."""
    data = json.loads(path.read_text())
    components: list[Component] = []
    for section in ("dependencies", "devDependencies"):
        for name, ver_spec in (data.get(section) or {}).items():
            version = ver_spec.lstrip("^~>=< ").split(" ")[0].strip() or "0.0.0"
            components.append(Component(
                name=name,
                version=version,
                purl=_make_purl("npm", name, version),
                ecosystem="npm",
            ))
    return components


def parse_go_mod(path: Path) -> list[Component]:
    """Parse Go go.mod into components."""
    components: list[Component] = []
    in_require = False
    for line in path.read_text().splitlines():
        line = line.strip()
        if line.startswith("require ("):
            in_require = True
            continue
        if in_require and line == ")":
            in_require = False
            continue
        if in_require or line.startswith("require "):
            parts = line.replace("require ", "").split()
            if len(parts) >= 2 and not parts[0].startswith("//"):
                name, version = parts[0], parts[1].lstrip("v")
                components.append(Component(
                    name=name,
                    version=version,
                    purl=_make_purl("Go", name, version),
                    ecosystem="Go",
                ))
    return components


def parse_pyproject_toml(path: Path) -> list[Component]:
    """Parse pyproject.toml [project].dependencies."""
    try:
        import tomllib  # type: ignore[import]
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore[import,no-redef]
        except ImportError:
            return []
    with path.open("rb") as fh:
        data = tomllib.load(fh)
    components: list[Component] = []
    for dep_str in data.get("project", {}).get("dependencies", []):
        m = re.match(r"^([A-Za-z0-9_\-\.]+)\s*(?:>=|==|~=|<=)?\s*([A-Za-z0-9._\-]*)", dep_str)
        if m:
            name = m.group(1)
            version = m.group(2) or "unknown"
            components.append(Component(
                name=name,
                version=version,
                purl=_make_purl("PyPI", name.lower(), version),
                ecosystem="PyPI",
            ))
    return components


def detect_and_parse(path: Path) -> list[Component]:
    """Auto-detect manifest type and parse components."""
    name = path.name.lower()
    if name in ("requirements.txt", "requirements-dev.txt"):
        return parse_requirements_txt(path)
    if name == "package.json":
        return parse_package_json(path)
    if name == "go.mod":
        return parse_go_mod(path)
    if name == "pyproject.toml":
        return parse_pyproject_toml(path)
    raise ValueError(f"Unsupported manifest: {path.name}")


# ── SBOM document ──────────────────────────────────────────────────────────────

@dataclass
class SBOMDocument:
    """A Software Bill of Materials document."""

    serial_number: str
    version: int
    metadata_timestamp: str
    components: list[Component]
    source_manifest: str

    @classmethod
    def from_components(cls, components: list[Component], source: str) -> "SBOMDocument":
        """Create SBOM from a list of components."""
        return cls(
            serial_number=f"urn:uuid:{uuid.uuid4()}",
            version=1,
            metadata_timestamp=datetime.now(timezone.utc).isoformat(),
            components=components,
            source_manifest=source,
        )

    def to_cyclonedx(self) -> dict[str, Any]:
        """Export as CycloneDX JSON."""
        return {
            "bomFormat": SBOM_FORMAT,
            "specVersion": SBOM_SPEC_VERSION,
            "serialNumber": self.serial_number,
            "version": self.version,
            "metadata": {
                "timestamp": self.metadata_timestamp,
                "tools": [{"name": "sbom-generator", "version": "0.1.0"}],
            },
            "components": [c.to_cyclonedx() for c in self.components],
        }

    def to_spdx(self) -> dict[str, Any]:
        """Export as SPDX 2.3 JSON."""
        return {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": self.source_manifest,
            "documentNamespace": self.serial_number,
            "creationInfo": {
                "created": self.metadata_timestamp,
                "creators": ["Tool: sbom-generator-0.1.0"],
            },
            "packages": [c.to_spdx() for c in self.components],
        }

    def summary(self) -> dict[str, Any]:
        """Return summary statistics."""
        by_eco: dict[str, int] = {}
        for c in self.components:
            by_eco[c.ecosystem] = by_eco.get(c.ecosystem, 0) + 1
        return {
            "total_components": len(self.components),
            "by_ecosystem": by_eco,
            "serial_number": self.serial_number,
            "generated_at": self.metadata_timestamp,
        }
