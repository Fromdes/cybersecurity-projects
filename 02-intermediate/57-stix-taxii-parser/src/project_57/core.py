"""STIX 2.x bundle parser and TAXII 2.1 client wrapper."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# STIX object types we care about
# ---------------------------------------------------------------------------

class STIXType(str, Enum):
    INDICATOR = "indicator"
    MALWARE = "malware"
    THREAT_ACTOR = "threat-actor"
    ATTACK_PATTERN = "attack-pattern"
    CAMPAIGN = "campaign"
    INTRUSION_SET = "intrusion-set"
    TOOL = "tool"
    VULNERABILITY = "vulnerability"
    OBSERVED_DATA = "observed-data"
    RELATIONSHIP = "relationship"
    IDENTITY = "identity"
    REPORT = "report"


# ---------------------------------------------------------------------------
# Parsed objects
# ---------------------------------------------------------------------------

@dataclass
class STIXObject:
    """Generic STIX Domain Object."""

    stix_id: str
    stix_type: str
    spec_version: str
    created: str
    modified: str
    name: str
    description: str
    raw: dict[str, Any]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "STIXObject":
        return cls(
            stix_id=data.get("id", ""),
            stix_type=data.get("type", ""),
            spec_version=data.get("spec_version", "2.1"),
            created=data.get("created", ""),
            modified=data.get("modified", ""),
            name=data.get("name", data.get("id", "")),
            description=data.get("description", ""),
            raw=data,
        )


@dataclass
class STIXIndicator(STIXObject):
    """STIX Indicator object with pattern extraction."""

    pattern: str = ""
    pattern_type: str = ""
    valid_from: str = ""
    kill_chain_phases: list[str] = field(default_factory=list)
    labels: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "STIXIndicator":  # type: ignore[override]
        base = STIXObject.from_dict(data)
        return cls(
            **base.__dict__,
            pattern=data.get("pattern", ""),
            pattern_type=data.get("pattern_type", "stix"),
            valid_from=data.get("valid_from", ""),
            kill_chain_phases=[
                p.get("phase_name", "") for p in data.get("kill_chain_phases", [])
            ],
            labels=data.get("labels", []),
        )

    def extract_ioc_value(self) -> str | None:
        """Try to extract a simple IOC value from the STIX pattern."""
        import re
        # e.g. [ipv4-addr:value = '1.2.3.4']
        m = re.search(r"'([^']+)'", self.pattern)
        return m.group(1) if m else None


# ---------------------------------------------------------------------------
# Bundle parser
# ---------------------------------------------------------------------------

@dataclass
class STIXBundle:
    """Parsed STIX 2.x bundle."""

    bundle_id: str
    spec_version: str
    objects: list[STIXObject] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "STIXBundle":
        bundle = cls(
            bundle_id=data.get("id", ""),
            spec_version=data.get("spec_version", "2.1"),
        )
        for obj in data.get("objects", []):
            stix_type = obj.get("type", "")
            if stix_type == STIXType.INDICATOR.value:
                bundle.objects.append(STIXIndicator.from_dict(obj))
            else:
                bundle.objects.append(STIXObject.from_dict(obj))
        return bundle

    @classmethod
    def from_file(cls, path: Path) -> "STIXBundle":
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls.from_dict(data)

    @classmethod
    def from_string(cls, content: str) -> "STIXBundle":
        return cls.from_dict(json.loads(content))

    def indicators(self) -> list[STIXIndicator]:
        return [o for o in self.objects if isinstance(o, STIXIndicator)]

    def by_type(self, stix_type: str) -> list[STIXObject]:
        return [o for o in self.objects if o.stix_type == stix_type]

    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for obj in self.objects:
            counts[obj.stix_type] = counts.get(obj.stix_type, 0) + 1
        return counts


# ---------------------------------------------------------------------------
# TAXII 2.1 client (lightweight, uses only requests)
# ---------------------------------------------------------------------------

@dataclass
class TAXIIClient:
    """Minimal TAXII 2.1 read-only client."""

    server_url: str
    username: str = ""
    password: str = ""
    verify_ssl: bool = True
    timeout: int = 30

    def _headers(self) -> dict[str, str]:
        return {
            "Accept": "application/taxii+json;version=2.1",
            "Content-Type": "application/taxii+json;version=2.1",
        }

    def _auth(self) -> tuple[str, str] | None:
        if self.username:
            return (self.username, self.password)
        return None

    def discover(self) -> dict[str, Any]:
        """GET /taxii/ — server discovery."""
        try:
            import requests
        except ImportError as exc:
            raise ImportError("pip install requests") from exc
        url = self.server_url.rstrip("/") + "/taxii/"
        resp = requests.get(
            url, headers=self._headers(), auth=self._auth(),
            verify=self.verify_ssl, timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def get_collections(self, api_root: str) -> list[dict[str, Any]]:
        """GET /<api_root>/collections/"""
        try:
            import requests
        except ImportError as exc:
            raise ImportError("pip install requests") from exc
        url = f"{self.server_url.rstrip('/')}/{api_root.strip('/')}/collections/"
        resp = requests.get(
            url, headers=self._headers(), auth=self._auth(),
            verify=self.verify_ssl, timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json().get("collections", [])

    def get_objects(
        self,
        api_root: str,
        collection_id: str,
        *,
        added_after: str | None = None,
        limit: int = 100,
    ) -> STIXBundle:
        """Fetch STIX objects from a collection."""
        try:
            import requests
        except ImportError as exc:
            raise ImportError("pip install requests") from exc
        url = (
            f"{self.server_url.rstrip('/')}/{api_root.strip('/')}/"
            f"collections/{collection_id}/objects/"
        )
        params: dict[str, Any] = {"limit": limit}
        if added_after:
            params["added_after"] = added_after

        resp = requests.get(
            url, headers=self._headers(), auth=self._auth(),
            params=params, verify=self.verify_ssl, timeout=self.timeout,
        )
        resp.raise_for_status()
        return STIXBundle.from_dict(resp.json())
