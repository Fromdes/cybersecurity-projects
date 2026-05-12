# Architecture — WebAuthn/FIDO2 Verifier

## Components

```
core.py   AuthenticatorData, WebAuthnVerifier, ChallengeStore, CredentialStore
cli.py    Click CLI (parse-authdata / demo / issue-challenge)
```

## W3C WebAuthn §7.1 Registration (verified steps)

```
1. Issue challenge → ChallengeStore.issue()
2. Receive clientDataJSON + authenticatorData from browser
3. verify_client_data()  → type=webauthn.create, challenge match, origin match
4. parse_authenticator_data() → AuthenticatorData
5. verify_authenticator_data() → rpIdHash, UP flag, sign counter
6. Store credential → CredentialStore.store()
```

## W3C WebAuthn §7.2 Authentication (verified steps)

```
1. Issue challenge → ChallengeStore.issue()
2. Receive clientDataJSON + authenticatorData from browser
3. verify_client_data()  → type=webauthn.get, challenge match, origin match
4. ChallengeStore.consume() — prevents replay
5. parse_authenticator_data()
6. verify_authenticator_data() → rpIdHash, UP, sign counter > stored
7. Update stored sign counter
```

## Security Properties

- Challenges are single-use (consume() removes from set)
- Sign counter replay detection (stored > received → COUNTER_REPLAY)
- Origin binding prevents cross-origin token theft
- RP ID hash verified with `secrets.compare_digest` (constant-time)
