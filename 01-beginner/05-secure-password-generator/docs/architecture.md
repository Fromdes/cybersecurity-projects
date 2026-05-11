# Architecture — Project 05: Secure Password Generator

## Why `secrets` and not `random`?

`random` uses a Mersenne Twister PRNG which is not cryptographically secure — an
observer who sees a few outputs can predict future outputs. `secrets` uses the OS
entropy pool (urandom / CryptGenRandom) which is unpredictable by design.

## Rejection Sampling

When `require_each_class=True`, the generator draws a full password and discards it
if any required class is absent, looping until all classes are present. The expected
number of retries is extremely small (< 2) for typical configurations. This is safer
than "pre-seed one character of each class then fill randomly" because it avoids
introducing patterns that reduce entropy.

## Entropy Calculation

```
pool = |alphabet|   (all enabled character classes, minus ambiguous if set)
entropy = length × log₂(pool)
```

This is a best-case (naive) estimate. Real-world entropy may be lower if the password
follows a predictable structure (e.g. starts with upper, ends with digit).
