# Threat Model — Behavioral Authentication

## STRIDE Analysis

| Threat | Component | Mitigation |
|---|---|---|
| Spoofing | Keystroke replay | Timing is naturally unique per session |
| Tampering | Profile JSON | Store profiles in access-controlled directory |
| Repudiation | Verification decisions | Log acceptance/rejection with score |
| Information Disclosure | Profile stats | Profile reveals mean timing, not keystrokes |
| DoS | Enrollment process | Requires ≥3 samples; single-shot attacks rejected |
| Elevation of Privilege | Impostor access | Mean z-score threshold prevents acceptance |

## Limitations

- Threshold tuning needed per deployment (FAR vs FRR trade-off)
- Typing pattern varies with keyboard type, fatigue, injuries
- Not suitable as sole authentication factor — use as 2nd factor
