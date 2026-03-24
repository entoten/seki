# Standards Compliance

seki implements the following RFCs and standards:

## OAuth 2.0 / 2.1
| Standard | Status | Notes |
|----------|--------|-------|
| RFC 6749 — OAuth 2.0 Authorization Framework | Implemented | Authorization Code, Client Credentials, Refresh Token |
| RFC 6750 — Bearer Token Usage | Implemented | |
| RFC 7636 — PKCE | Implemented | S256 required for public clients |
| RFC 7009 — Token Revocation | Implemented | |
| RFC 7662 — Token Introspection | Implemented | |
| RFC 8628 — Device Authorization Grant | Implemented | |
| OAuth 2.1 (draft-ietf-oauth-v2-1) | Compliant | PKCE required, implicit/ROPC rejected |
| RFC 9207 — AS Issuer Identification | Implemented | `iss` in authorization response |
| RFC 9068 — JWT Access Token Profile | Implemented | `at+jwt` typ, `jti`, `client_id` |
| RFC 8414 — OAuth AS Metadata | Implemented | `/.well-known/oauth-authorization-server` |
| RFC 9449 — DPoP | Planned | #67 |
| RFC 9126 — PAR | Planned | #68 |
| RFC 8693 — Token Exchange | Planned | |

## OpenID Connect
| Standard | Status | Notes |
|----------|--------|-------|
| OpenID Connect Core 1.0 | Implemented | |
| OpenID Connect Discovery 1.0 | Implemented | |
| OpenID Connect RP-Initiated Logout | Implemented | |

## Authentication
| Standard | Status | Notes |
|----------|--------|-------|
| WebAuthn Level 2 (Passkeys) | Implemented | Registration, authentication, discoverable login |
| RFC 6238 — TOTP | Implemented | |

## Identity Management
| Standard | Status | Notes |
|----------|--------|-------|
| SCIM 2.0 (RFC 7643/7644) | Implemented | Users and Groups |

## API & Error Handling
| Standard | Status | Notes |
|----------|--------|-------|
| RFC 9457 — Problem Details for HTTP APIs | Implemented | With error codes |
| OpenAPI 3.0 | Documented | Interactive explorer at /api/docs |

## Token & Key Standards
| Standard | Status | Notes |
|----------|--------|-------|
| RFC 7519 — JWT (JSON Web Token) | Implemented | Access tokens, ID tokens |
| RFC 7517 — JWK (JSON Web Key) | Implemented | JWKS endpoint |
| RFC 7518 — JWA (JSON Web Algorithms) | Implemented | EdDSA (Ed25519) |
| RFC 7515 — JWS (JSON Web Signature) | Implemented | Compact serialization |
| RFC 7638 — JWK Thumbprint | Implemented | DPoP key binding |

## Security
| Standard | Status | Notes |
|----------|--------|-------|
| RFC 9700 — OAuth 2.0 Security BCP | Implemented | PKCE required, exact redirect URI matching, refresh token rotation |
| RFC 8705 — mTLS Certificate-Bound Tokens | Planned | |
| FAPI 2.0 | Future | |
