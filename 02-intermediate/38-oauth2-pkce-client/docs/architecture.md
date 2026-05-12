# Architecture — OAuth2 PKCE Client

## Components

```
cli.py     Click CLI (challenge / auth-url / exchange commands)
core.py    PKCE generation, URL construction, token exchange, state verification
```

## OAuth2 PKCE Flow

```
1. generate_pkce_challenge()
   → code_verifier (secret, stored locally)
   → code_challenge = BASE64URL(SHA256(verifier))

2. build_authorization_url()
   → redirect user to IdP with code_challenge + state

3. IdP redirects back with ?code=...&state=...

4. verify_state()   ← CSRF protection

5. exchange_code_for_tokens()
   → POST code + code_verifier to token endpoint
   → IdP verifies SHA256(verifier) == challenge
   → Returns access_token
```

## Security Properties

- Verifier generated with `secrets.token_bytes` (CSPRNG)
- Only S256 method supported — `plain` omitted (vulnerable to eavesdropping)
- State verified with `secrets.compare_digest` (constant-time)
- Verifier never returned in `describe_pkce()` to prevent accidental logging
