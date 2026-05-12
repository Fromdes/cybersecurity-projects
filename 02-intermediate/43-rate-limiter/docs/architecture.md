# Architecture — Rate Limiter

## Algorithms

| Algorithm | State | Burst | Precision | Boundary burst |
|-----------|-------|-------|-----------|---------------|
| Token Bucket | tokens + last_refill | Yes | Medium | No |
| Sliding Window | deque of timestamps | No | High | No |
| Fixed Window | count + window_start | No | Low | Yes |

## Data Structures

```
TokenBucketLimiter
  _buckets: dict[key → _TokenBucket(tokens, last_refill)]

SlidingWindowLimiter
  _logs: dict[key → deque[float]]   ← timestamps, evicted as they age out

FixedWindowLimiter
  _windows: dict[key → _FixedWindow(count, window_start)]
```

## Decision Fields

```
RateLimitDecision(
    result:       ALLOWED | DENIED
    remaining:    tokens / requests left in current window
    reset_at:     epoch when limit resets
    retry_after:  seconds until next allowed request
)
```

These map directly to HTTP headers:
- `X-RateLimit-Remaining`
- `X-RateLimit-Reset`
- `Retry-After`
