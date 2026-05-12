# Architecture — Behavioral Authentication

## Components

```
cli.py         → Click interface (enroll, verify, demo)
core.py        → Feature extraction + profile building + verification
  extract_features()       → list[KeyEvent] → KeystrokeSample
  build_profile()          → samples → BehavioralProfile
  verify_sample()          → profile + sample → VerificationResult
  generate_synthetic_sample() → keys → KeystrokeSample (for testing)
```

## Feature Space

| Feature | Count | Description |
|---|---|---|
| Dwell time | N keys | Duration each key is held down |
| Flight time | N-1 | Time between consecutive key releases |
| Digraph time | N-1 | Time between consecutive key presses |

## Verification Distance

Mean z-score: `mean(|x_i - μ_i| / σ_i)` across all features.
Lower = more similar to enrolled profile.
