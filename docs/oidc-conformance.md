# OIDC Conformance Testing

## Overview
The OpenID Foundation provides a conformance test suite for OIDC providers.
seki targets the "Basic OP" and "Config OP" test profiles.

## Prerequisites
- Docker (for running the conformance suite)
- seki running locally

## Quick Test (Internal)
seki includes an internal conformance test that validates core OIDC behavior:
- Discovery endpoint returns all required fields
- JWKS endpoint returns valid JWK Set
- Authorization Code + PKCE flow works end-to-end
- Token endpoint returns valid JWT tokens
- UserInfo endpoint returns correct claims
- Token Introspection works
- Token Revocation works
- Implicit grant is rejected (OAuth 2.1)
- ROPC grant is rejected (OAuth 2.1)

Run the internal conformance suite:
```
go test -v -run TestOIDCConformance ./internal/oidc/...
```

## Running the OpenID Foundation Suite
1. Start seki: `docker compose up -d`
2. Run the conformance suite:
   ```
   docker run --network host \
     -e TEST_CONFIG=... \
     openid-certification/conformance-suite
   ```
3. Select "Basic OP" profile
4. Configure issuer URL: http://localhost:8080

## Current Status
| Profile | Status |
|---------|--------|
| Basic OP | Targeted |
| Config OP | Targeted |
| Dynamic OP | Not targeted |
| Hybrid OP | Not targeted (no implicit) |

## Known Deviations
- seki does not support the implicit grant (OAuth 2.1 decision)
- PKCE is required for all public clients
