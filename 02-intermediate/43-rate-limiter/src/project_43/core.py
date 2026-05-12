"""Rate Limiter — token bucket, sliding window, and fixed window algorithms.

Defends against: T1110 (Brute Force), T1078 (Valid Accounts — credential stuffing),
T1498 (Network DoS — application-layer flood).
"""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass
from enum import StrEnum

logger = logging.getLogger(__name__)


class LimitResult(StrEnum):
    """Outcome of a rate-limit check."""

    ALLOWED = "allowed"
    DENIED = "denied"


@dataclass(frozen=True)
class RateLimitDecision:
    """Result of a single rate-limit check."""

    result: LimitResult
    key: str
    remaining: int
    reset_at: float
    retry_after: float

    @property
    def allowed(self) -> bool:
        """True when the request is permitted."""
        return self.result == LimitResult.ALLOWED


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------

class RateLimiter(ABC):
    """Abstract base for rate limiter implementations."""

    @abstractmethod
    def check(self, key: str) -> RateLimitDecision:
        """Check and consume one token for the given key.

        Args:
            key: Identifier (user ID, IP, API key, etc.).

        Returns:
            RateLimitDecision with allow/deny verdict and headers.
        """

    @abstractmethod
    def reset(self, key: str) -> None:
        """Clear the rate-limit state for a key.

        Args:
            key: Identifier to reset.
        """

    @abstractmethod
    def peek(self, key: str) -> RateLimitDecision:
        """Check without consuming a token.

        Args:
            key: Identifier to inspect.

        Returns:
            RateLimitDecision (does not decrement counter).
        """


# ---------------------------------------------------------------------------
# Token Bucket
# ---------------------------------------------------------------------------

@dataclass
class _TokenBucket:
    tokens: float
    last_refill: float


class TokenBucketLimiter(RateLimiter):
    """Token bucket rate limiter — smooth out bursts while allowing short peaks.

    Tokens refill continuously at `rate` per second up to `capacity`.
    """

    def __init__(self, capacity: int, rate: float) -> None:
        """Args:
            capacity: Maximum token capacity (burst size).
            rate: Token refill rate per second.
        """
        if capacity <= 0 or rate <= 0:
            raise ValueError("capacity and rate must be positive")
        self._capacity = capacity
        self._rate = rate
        self._buckets: dict[str, _TokenBucket] = {}

    def _get_or_create(self, key: str) -> _TokenBucket:
        if key not in self._buckets:
            self._buckets[key] = _TokenBucket(tokens=float(self._capacity), last_refill=time.monotonic())
        return self._buckets[key]

    def _refill(self, bucket: _TokenBucket) -> None:
        now = time.monotonic()
        elapsed = now - bucket.last_refill
        bucket.tokens = min(float(self._capacity), bucket.tokens + elapsed * self._rate)
        bucket.last_refill = now

    def check(self, key: str) -> RateLimitDecision:
        """Consume one token; deny if bucket is empty."""
        bucket = self._get_or_create(key)
        self._refill(bucket)

        if bucket.tokens >= 1.0:
            bucket.tokens -= 1.0
            remaining = int(bucket.tokens)
            reset_at = time.time() + (self._capacity - bucket.tokens) / self._rate
            logger.debug("RateLimit ALLOW key=%s remaining=%d", key, remaining)
            return RateLimitDecision(LimitResult.ALLOWED, key, remaining, reset_at, 0.0)

        retry_after = (1.0 - bucket.tokens) / self._rate
        logger.warning("RateLimit DENY key=%s retry_after=%.2f", key, retry_after)
        return RateLimitDecision(LimitResult.DENIED, key, 0, time.time() + retry_after, retry_after)

    def reset(self, key: str) -> None:
        """Refill bucket to capacity."""
        if key in self._buckets:
            self._buckets[key].tokens = float(self._capacity)
            self._buckets[key].last_refill = time.monotonic()

    def peek(self, key: str) -> RateLimitDecision:
        """Check without consuming."""
        bucket = self._get_or_create(key)
        self._refill(bucket)
        if bucket.tokens >= 1.0:
            return RateLimitDecision(LimitResult.ALLOWED, key, int(bucket.tokens), time.time(), 0.0)
        retry_after = (1.0 - bucket.tokens) / self._rate
        return RateLimitDecision(LimitResult.DENIED, key, 0, time.time() + retry_after, retry_after)


# ---------------------------------------------------------------------------
# Sliding Window Log
# ---------------------------------------------------------------------------

class SlidingWindowLimiter(RateLimiter):
    """Sliding window log — precise rate limiting with per-request timestamps."""

    def __init__(self, limit: int, window_seconds: float) -> None:
        """Args:
            limit: Maximum requests allowed within the window.
            window_seconds: Window duration in seconds.
        """
        if limit <= 0 or window_seconds <= 0:
            raise ValueError("limit and window_seconds must be positive")
        self._limit = limit
        self._window = window_seconds
        self._logs: dict[str, deque[float]] = {}

    def _get_log(self, key: str) -> deque[float]:
        if key not in self._logs:
            self._logs[key] = deque()
        return self._logs[key]

    def _evict_old(self, log: deque[float], now: float) -> None:
        cutoff = now - self._window
        while log and log[0] <= cutoff:
            log.popleft()

    def check(self, key: str) -> RateLimitDecision:
        """Record timestamp and check against limit."""
        log = self._get_log(key)
        now = time.time()
        self._evict_old(log, now)

        if len(log) < self._limit:
            log.append(now)
            remaining = self._limit - len(log)
            reset_at = log[0] + self._window if log else now + self._window
            return RateLimitDecision(LimitResult.ALLOWED, key, remaining, reset_at, 0.0)

        oldest = log[0]
        retry_after = (oldest + self._window) - now
        return RateLimitDecision(LimitResult.DENIED, key, 0, oldest + self._window, max(0.0, retry_after))

    def reset(self, key: str) -> None:
        """Clear the request log for a key."""
        if key in self._logs:
            self._logs[key].clear()

    def peek(self, key: str) -> RateLimitDecision:
        """Check without recording."""
        log = self._get_log(key)
        now = time.time()
        self._evict_old(log, now)
        if len(log) < self._limit:
            return RateLimitDecision(LimitResult.ALLOWED, key, self._limit - len(log), now + self._window, 0.0)
        oldest = log[0]
        retry_after = (oldest + self._window) - now
        return RateLimitDecision(LimitResult.DENIED, key, 0, oldest + self._window, max(0.0, retry_after))


# ---------------------------------------------------------------------------
# Fixed Window
# ---------------------------------------------------------------------------

@dataclass
class _FixedWindow:
    count: int
    window_start: float


class FixedWindowLimiter(RateLimiter):
    """Fixed window counter — simplest algorithm; susceptible to boundary bursts."""

    def __init__(self, limit: int, window_seconds: float) -> None:
        """Args:
            limit: Maximum requests per window.
            window_seconds: Window size in seconds.
        """
        if limit <= 0 or window_seconds <= 0:
            raise ValueError("limit and window_seconds must be positive")
        self._limit = limit
        self._window = window_seconds
        self._windows: dict[str, _FixedWindow] = {}

    def _get_window(self, key: str) -> _FixedWindow:
        now = time.time()
        win = self._windows.get(key)
        if win is None or (now - win.window_start) >= self._window:
            win = _FixedWindow(count=0, window_start=now)
            self._windows[key] = win
        return win

    def check(self, key: str) -> RateLimitDecision:
        """Increment counter; deny if limit exceeded in current window."""
        win = self._get_window(key)
        reset_at = win.window_start + self._window

        if win.count < self._limit:
            win.count += 1
            remaining = self._limit - win.count
            return RateLimitDecision(LimitResult.ALLOWED, key, remaining, reset_at, 0.0)

        retry_after = reset_at - time.time()
        return RateLimitDecision(LimitResult.DENIED, key, 0, reset_at, max(0.0, retry_after))

    def reset(self, key: str) -> None:
        """Reset the window for a key."""
        if key in self._windows:
            del self._windows[key]

    def peek(self, key: str) -> RateLimitDecision:
        """Check without incrementing."""
        win = self._get_window(key)
        reset_at = win.window_start + self._window
        if win.count < self._limit:
            return RateLimitDecision(LimitResult.ALLOWED, key, self._limit - win.count, reset_at, 0.0)
        retry_after = reset_at - time.time()
        return RateLimitDecision(LimitResult.DENIED, key, 0, reset_at, max(0.0, retry_after))
