"""Tests for Rate Limiter core logic."""

from __future__ import annotations

import time

import pytest

from project_43.core import (
    FixedWindowLimiter,
    SlidingWindowLimiter,
    TokenBucketLimiter,
)


class TestTokenBucketLimiter:
    def test_allows_up_to_capacity(self) -> None:
        lim = TokenBucketLimiter(capacity=5, rate=1.0)
        for _ in range(5):
            assert lim.check("u").allowed

    def test_denies_when_bucket_empty(self) -> None:
        lim = TokenBucketLimiter(capacity=3, rate=0.1)
        for _ in range(3):
            lim.check("u")
        assert not lim.check("u").allowed

    def test_refills_over_time(self) -> None:
        lim = TokenBucketLimiter(capacity=1, rate=100.0)
        lim.check("u")  # drain
        time.sleep(0.02)   # wait for refill
        assert lim.check("u").allowed

    def test_reset_refills(self) -> None:
        lim = TokenBucketLimiter(capacity=2, rate=0.1)
        lim.check("u")
        lim.check("u")
        lim.reset("u")
        assert lim.check("u").allowed

    def test_different_keys_independent(self) -> None:
        lim = TokenBucketLimiter(capacity=1, rate=0.1)
        lim.check("a")  # drain a
        assert lim.check("b").allowed  # b is full

    def test_invalid_params(self) -> None:
        with pytest.raises(ValueError):
            TokenBucketLimiter(capacity=0, rate=1.0)
        with pytest.raises(ValueError):
            TokenBucketLimiter(capacity=1, rate=0.0)

    def test_peek_does_not_consume(self) -> None:
        lim = TokenBucketLimiter(capacity=1, rate=0.1)
        lim.peek("u")
        assert lim.check("u").allowed

    def test_remaining_decrements(self) -> None:
        lim = TokenBucketLimiter(capacity=5, rate=1.0)
        d1 = lim.check("u")
        d2 = lim.check("u")
        assert d2.remaining < d1.remaining

    def test_retry_after_positive_on_deny(self) -> None:
        lim = TokenBucketLimiter(capacity=1, rate=0.5)
        lim.check("u")
        d = lim.check("u")
        assert not d.allowed
        assert d.retry_after > 0


class TestSlidingWindowLimiter:
    def test_allows_within_limit(self) -> None:
        lim = SlidingWindowLimiter(limit=5, window_seconds=10.0)
        for _ in range(5):
            assert lim.check("u").allowed

    def test_denies_at_limit(self) -> None:
        lim = SlidingWindowLimiter(limit=3, window_seconds=10.0)
        for _ in range(3):
            lim.check("u")
        assert not lim.check("u").allowed

    def test_allows_after_window_expires(self) -> None:
        lim = SlidingWindowLimiter(limit=1, window_seconds=0.1)
        lim.check("u")
        time.sleep(0.15)
        assert lim.check("u").allowed

    def test_reset_clears_log(self) -> None:
        lim = SlidingWindowLimiter(limit=1, window_seconds=10.0)
        lim.check("u")
        lim.reset("u")
        assert lim.check("u").allowed

    def test_peek_does_not_record(self) -> None:
        lim = SlidingWindowLimiter(limit=1, window_seconds=10.0)
        lim.peek("u")
        assert lim.check("u").allowed

    def test_different_keys_independent(self) -> None:
        lim = SlidingWindowLimiter(limit=1, window_seconds=10.0)
        lim.check("a")
        assert lim.check("b").allowed

    def test_invalid_params(self) -> None:
        with pytest.raises(ValueError):
            SlidingWindowLimiter(limit=0, window_seconds=1.0)


class TestFixedWindowLimiter:
    def test_allows_within_limit(self) -> None:
        lim = FixedWindowLimiter(limit=3, window_seconds=10.0)
        for _ in range(3):
            assert lim.check("u").allowed

    def test_denies_at_limit(self) -> None:
        lim = FixedWindowLimiter(limit=2, window_seconds=10.0)
        lim.check("u")
        lim.check("u")
        assert not lim.check("u").allowed

    def test_resets_after_window(self) -> None:
        lim = FixedWindowLimiter(limit=1, window_seconds=0.1)
        lim.check("u")
        time.sleep(0.15)
        assert lim.check("u").allowed

    def test_reset_clears_window(self) -> None:
        lim = FixedWindowLimiter(limit=1, window_seconds=10.0)
        lim.check("u")
        lim.reset("u")
        assert lim.check("u").allowed

    def test_peek_does_not_increment(self) -> None:
        lim = FixedWindowLimiter(limit=1, window_seconds=10.0)
        lim.peek("u")
        assert lim.check("u").allowed

    def test_invalid_params(self) -> None:
        with pytest.raises(ValueError):
            FixedWindowLimiter(limit=5, window_seconds=0.0)
