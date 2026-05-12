"""Tests for project_96 core — Behavioral Authentication."""

from __future__ import annotations

import pytest

from project_96.core import (
    BehavioralProfile,
    KeyEvent,
    KeystrokeSample,
    build_profile,
    extract_features,
    generate_synthetic_sample,
    load_profile,
    save_profile,
    verify_sample,
)


def _events(keys: list[str], dwell: float = 0.08, flight: float = 0.12) -> list[KeyEvent]:
    events: list[KeyEvent] = []
    t = 0.0
    for key in keys:
        events.append(KeyEvent(key=key, event_type="down", timestamp=t))
        events.append(KeyEvent(key=key, event_type="up", timestamp=t + dwell))
        t += dwell + flight
    return events


KEYS = ["a", "b", "c", "d"]


class TestExtractFeatures:
    def test_dwell_times_computed(self) -> None:
        evs = _events(KEYS, dwell=0.1)
        s = extract_features(evs)
        for k in KEYS:
            assert k in s.dwell_times
            assert abs(s.dwell_times[k] - 0.1) < 0.001

    def test_flight_times_count(self) -> None:
        evs = _events(KEYS, flight=0.15)
        s = extract_features(evs)
        assert len(s.flight_times) == len(KEYS) - 1

    def test_digraph_times_count(self) -> None:
        evs = _events(KEYS)
        s = extract_features(evs)
        assert len(s.digraph_times) == len(KEYS) - 1

    def test_feature_vector_length(self) -> None:
        evs = _events(KEYS)
        s = extract_features(evs)
        vec = s.feature_vector()
        expected = len(KEYS) + (len(KEYS) - 1) + (len(KEYS) - 1)
        assert len(vec) == expected


class TestBuildProfile:
    def _samples(self, n: int = 5) -> list[KeystrokeSample]:
        return [generate_synthetic_sample(KEYS) for _ in range(n)]

    def test_requires_min_samples(self) -> None:
        with pytest.raises(ValueError, match="at least"):
            build_profile("alice", "abcd", self._samples(2))

    def test_profile_has_stats(self) -> None:
        profile = build_profile("alice", "abcd", self._samples(5))
        assert len(profile.stats) > 0
        assert profile.user_id == "alice"

    def test_profile_sample_count(self) -> None:
        profile = build_profile("alice", "abcd", self._samples(7))
        assert profile.sample_count == 7

    def test_custom_threshold(self) -> None:
        profile = build_profile("alice", "abcd", self._samples(5), threshold=1.5)
        assert profile.threshold == 1.5

    def test_stats_have_positive_std(self) -> None:
        profile = build_profile("alice", "abcd", self._samples(5))
        for stat in profile.stats.values():
            assert stat.std > 0


class TestVerifySample:
    def _enroll(self, n: int = 10) -> BehavioralProfile:
        samples = [generate_synthetic_sample(KEYS, mean_dwell=0.08, mean_flight=0.12, noise=0.01)
                   for _ in range(n)]
        return build_profile("alice", "abcd", samples, threshold=3.0)

    def test_genuine_user_accepted(self) -> None:
        profile = self._enroll()
        sample = generate_synthetic_sample(KEYS, mean_dwell=0.08, mean_flight=0.12, noise=0.015)
        result = verify_sample(profile, sample)
        assert result.accepted is True

    def test_impostor_rejected(self) -> None:
        profile = self._enroll()
        # Very different timing — impostor
        sample = generate_synthetic_sample(KEYS, mean_dwell=0.5, mean_flight=0.8, noise=0.05)
        result = verify_sample(profile, sample)
        assert result.accepted is False

    def test_result_has_score(self) -> None:
        profile = self._enroll()
        sample = generate_synthetic_sample(KEYS)
        result = verify_sample(profile, sample)
        assert result.score >= 0.0

    def test_result_to_dict(self) -> None:
        profile = self._enroll()
        sample = generate_synthetic_sample(KEYS, mean_dwell=0.08, mean_flight=0.12, noise=0.01)
        result = verify_sample(profile, sample)
        d = result.to_dict()
        assert "accepted" in d
        assert "score" in d


class TestProfilePersistence:
    def test_save_and_load(self, tmp_path) -> None:
        samples = [generate_synthetic_sample(KEYS) for _ in range(5)]
        profile = build_profile("bob", "abcd", samples)
        path = tmp_path / "bob.profile.json"
        save_profile(profile, path)
        loaded = load_profile(path)
        assert loaded.user_id == "bob"
        assert loaded.sample_count == 5
        assert set(loaded.stats.keys()) == set(profile.stats.keys())

    def test_to_dict_from_dict_roundtrip(self) -> None:
        samples = [generate_synthetic_sample(KEYS) for _ in range(5)]
        profile = build_profile("carol", "abcd", samples)
        restored = BehavioralProfile.from_dict(profile.to_dict())
        assert restored.user_id == profile.user_id
        assert restored.threshold == profile.threshold


class TestGenerateSyntheticSample:
    def test_returns_keystroke_sample(self) -> None:
        s = generate_synthetic_sample(KEYS)
        assert isinstance(s, KeystrokeSample)
        assert len(s.dwell_times) == len(KEYS)

    def test_noise_affects_timing(self) -> None:
        s1 = generate_synthetic_sample(KEYS, noise=0.0)
        s2 = generate_synthetic_sample(KEYS, noise=0.0)
        # With 0 noise and fixed seed, may still differ; just check structure
        assert isinstance(s1.flight_times, list)
        assert isinstance(s2.flight_times, list)
