# Threat Model — Project 13: HMAC Message Authenticator

## Assets

| Asset | Sensitivity |
|---|---|
| Shared HMAC key | Critical — loss allows tag forgery |
| Message + tag pair | Medium — reveals data was authenticated; tag leaks nothing about the key |

## Threat Actors

- Network attacker intercepting messages in transit
- Insider who has the message but not the key
- Timing oracle attacker probing verification responses

## STRIDE Analysis

| Threat | Vector | Mitigation |
|---|---|---|
| **Spoofing** | Attacker forges an HMAC without the key | Computationally infeasible for SHA-256/512 with a 256-bit key |
| **Tampering** | Attacker modifies the message and updates the tag | Cannot recompute a valid tag without the key |
| **Repudiation** | Sender denies sending a message | HMAC proves the message was created by a key-holder (non-repudiation requires asymmetric crypto — see Project 09) |
| **Information Disclosure** | Timing side-channel leaks digest bytes | `hmac.compare_digest` constant-time comparison |
| **Denial of Service** | Flooding the verifier with invalid tags | No state involved; rejection is O(1) |
| **Elevation of Privilege** | Length-extension attack on naked SHA-256 | HMAC construction prevents length extension attacks |

## Assumptions

1. The shared key is distributed out-of-band (e.g., encrypted channel, key agreement).
2. Both parties use the same algorithm and encoding.
3. The key is never logged, stored in plaintext, or included in messages.
