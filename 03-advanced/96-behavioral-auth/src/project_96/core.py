"""Behavioral Authentication — keystroke dynamics profiling and statistical verification."""

from __future__ import annotations

import json
import math
import statistics
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# ── Keystroke event ───────────────────────────────────────────────────────────

@dataclass(frozen=True)
class KeyEvent:
    """A single key press/release event."""

    key: str
    event_type: str  # "down" or "up"
    timestamp: float  # seconds


@dataclass(frozen=True)
class KeystrokeSample:
    """Extracted timing features from one typed passphrase attempt."""

    dwell_times: dict[str, float]
    flight_times: list[float]
    digraph_times: dict[str, float]

    def feature_vector(self) -> list[float]:
        """Return a flat ordered feature vector."""
        return list(self.dwell_times.values()) + self.flight_times + list(self.digraph_times.values())


def extract_features(events: list[KeyEvent]) -> KeystrokeSample:
    """Extract dwell times, flight times, and digraph times from key events."""
    downs: dict[str, float] = {}
    ups: dict[str, float] = {}
    key_order: list[str] = []

    for ev in events:
        if ev.event_type == "down":
            downs[ev.key] = ev.timestamp
            key_order.append(ev.key)
        else:
            ups[ev.key] = ev.timestamp

    dwell_times: dict[str, float] = {}
    for key in key_order:
        if key in downs and key in ups:
            dwell_times[key] = max(0.0, ups[key] - downs[key])

    flight_times: list[float] = []
    for i in range(1, len(key_order)):
        prev, curr = key_order[i - 1], key_order[i]
        if prev in ups and curr in downs:
            flight_times.append(max(0.0, downs[curr] - ups[prev]))

    digraph_times: dict[str, float] = {}
    for i in range(1, len(key_order)):
        prev, curr = key_order[i - 1], key_order[i]
        pair = f"{prev}_{curr}"
        if prev in downs and curr in downs:
            digraph_times[pair] = max(0.0, downs[curr] - downs[prev])

    return KeystrokeSample(
        dwell_times=dwell_times,
        flight_times=flight_times,
        digraph_times=digraph_times,
    )


# ── Behavioral profile ────────────────────────────────────────────────────────

_MIN_SAMPLES = 3
_DEFAULT_THRESHOLD = 2.5
_MIN_STD = 0.01


@dataclass
class FeatureStat:
    """Mean and standard deviation for one timing feature."""

    mean: float
    std: float


@dataclass
class BehavioralProfile:
    """Statistical model of a user's keystroke dynamics."""

    user_id: str
    passphrase: str
    feature_keys: list[str]
    stats: dict[str, FeatureStat]
    sample_count: int
    threshold: float = _DEFAULT_THRESHOLD

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "user_id": self.user_id,
            "passphrase": self.passphrase,
            "feature_keys": self.feature_keys,
            "stats": {k: {"mean": v.mean, "std": v.std} for k, v in self.stats.items()},
            "sample_count": self.sample_count,
            "threshold": self.threshold,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "BehavioralProfile":
        """Deserialize from dict."""
        stats = {k: FeatureStat(v["mean"], v["std"]) for k, v in data["stats"].items()}
        return BehavioralProfile(
            user_id=data["user_id"],
            passphrase=data["passphrase"],
            feature_keys=data["feature_keys"],
            stats=stats,
            sample_count=data["sample_count"],
            threshold=data.get("threshold", _DEFAULT_THRESHOLD),
        )


def build_profile(
    user_id: str,
    passphrase: str,
    samples: list[KeystrokeSample],
    threshold: float = _DEFAULT_THRESHOLD,
) -> BehavioralProfile:
    """Build a behavioral profile from multiple enrollment samples."""
    if len(samples) < _MIN_SAMPLES:
        raise ValueError(f"Need at least {_MIN_SAMPLES} samples, got {len(samples)}")

    all_keys = list(samples[0].dwell_times.keys())
    flight_indices = list(range(len(samples[0].flight_times)))
    digraph_keys = list(samples[0].digraph_times.keys())
    feature_keys = (
        [f"dwell_{k}" for k in all_keys]
        + [f"flight_{i}" for i in flight_indices]
        + [f"digraph_{k}" for k in digraph_keys]
    )

    raw: dict[str, list[float]] = {k: [] for k in feature_keys}
    for sample in samples:
        for k in all_keys:
            raw[f"dwell_{k}"].append(sample.dwell_times.get(k, 0.0))
        for i in flight_indices:
            raw[f"flight_{i}"].append(sample.flight_times[i] if i < len(sample.flight_times) else 0.0)
        for k in digraph_keys:
            raw[f"digraph_{k}"].append(sample.digraph_times.get(k, 0.0))

    stats = {}
    for key, values in raw.items():
        mean = statistics.mean(values)
        std = statistics.stdev(values) if len(values) > 1 else _MIN_STD
        stats[key] = FeatureStat(mean=mean, std=max(std, _MIN_STD))

    return BehavioralProfile(
        user_id=user_id,
        passphrase=passphrase,
        feature_keys=feature_keys,
        stats=stats,
        sample_count=len(samples),
        threshold=threshold,
    )


# ── Verification ──────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class VerificationResult:
    """Result of a behavioral verification attempt."""

    accepted: bool
    score: float
    threshold: float
    user_id: str
    details: dict[str, float]

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "accepted": self.accepted,
            "score": round(self.score, 4),
            "threshold": self.threshold,
            "user_id": self.user_id,
        }


def verify_sample(profile: BehavioralProfile, sample: KeystrokeSample) -> VerificationResult:
    """Verify a keystroke sample against a behavioral profile using z-score distance."""
    all_keys = list(profile.stats.keys())
    feature_map = _sample_to_feature_map(sample)

    z_scores: dict[str, float] = {}
    for key in all_keys:
        value = feature_map.get(key, profile.stats[key].mean)
        stat = profile.stats[key]
        z_scores[key] = abs(value - stat.mean) / stat.std

    mean_z = statistics.mean(z_scores.values()) if z_scores else float("inf")
    accepted = mean_z <= profile.threshold

    return VerificationResult(
        accepted=accepted,
        score=mean_z,
        threshold=profile.threshold,
        user_id=profile.user_id,
        details=z_scores,
    )


def _sample_to_feature_map(sample: KeystrokeSample) -> dict[str, float]:
    """Convert a KeystrokeSample to a feature key → value dict."""
    result: dict[str, float] = {}
    for k, v in sample.dwell_times.items():
        result[f"dwell_{k}"] = v
    for i, v in enumerate(sample.flight_times):
        result[f"flight_{i}"] = v
    for k, v in sample.digraph_times.items():
        result[f"digraph_{k}"] = v
    return result


# ── Profile persistence ───────────────────────────────────────────────────────

def save_profile(profile: BehavioralProfile, path: Path) -> None:
    """Save a profile to a JSON file."""
    path.write_text(json.dumps(profile.to_dict(), indent=2))


def load_profile(path: Path) -> BehavioralProfile:
    """Load a profile from a JSON file."""
    return BehavioralProfile.from_dict(json.loads(path.read_text()))


# ── Synthetic sample generator (for testing/demo) ────────────────────────────

def generate_synthetic_sample(
    keys: list[str],
    mean_dwell: float = 0.08,
    mean_flight: float = 0.12,
    noise: float = 0.02,
) -> KeystrokeSample:
    """Generate a synthetic keystroke sample for testing."""
    import random

    rng = random.Random()
    events: list[KeyEvent] = []
    t = 0.0
    for key in keys:
        events.append(KeyEvent(key=key, event_type="down", timestamp=t))
        dwell = max(0.01, mean_dwell + rng.gauss(0, noise))
        events.append(KeyEvent(key=key, event_type="up", timestamp=t + dwell))
        flight = max(0.005, mean_flight + rng.gauss(0, noise))
        t += dwell + flight
    return extract_features(events)
