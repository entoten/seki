# Security Audit Report

**Project:** Seki Authentication Server
**Date:** 2026-03-24
**Scope:** Full codebase review (Issue #38)

---

## Automated Tool Results

### gosec (Static Analysis)

**Before hardening:** 52 issues (13 medium, 39 low)
**After hardening:** 13 issues (5 medium, 8 low)

Remaining findings are accepted risks:
- **G107 (URL from variable):** Webhook emitter and social login service make HTTP requests to configured URLs. These URLs come from the server YAML config, not user input.
- **G304 (File inclusion via variable):** Config loader and migration tools intentionally read files from paths specified at startup.
- **G104 (Unhandled errors):** JSON encoder writes to `http.ResponseWriter` where errors are non-actionable (broken client connection). CLI `fs.Parse` errors are likewise non-fatal.
- **G203 (Unescaped data in template):** The `renderError` function uses `text/plain` content type with server-controlled error codes, not user input.

### govulncheck (Dependency Vulnerabilities)

**Result:** No known vulnerabilities found in dependencies.

---

## OWASP Top 10 Checklist

### A01: Broken Access Control - PASS

| Check | Status | Notes |
|-------|--------|-------|
| All admin API endpoints require authentication | PASS | `RequireAPIKey` middleware wraps all `/api/v1/` routes |
| API key comparison is constant-time | PASS | Uses `crypto/subtle.ConstantTimeCompare` |
| Session ownership verified on revocation | PASS | `handleRevokeUserSession` checks `sess.UserID != userID` |
| Logout only via POST | PASS | Route registered as `POST /logout` |
| State-changing operations require POST/PATCH/DELETE | PASS | Go 1.22+ method routing enforced |

### A02: Cryptographic Failures - PASS

| Check | Status | Notes |
|-------|--------|-------|
| Ed25519 signing with proper key management | PASS | Keys stored with 0600 permissions |
| Passwords hashed with argon2id | PASS | `crypto.NewArgon2idHasher()` with 64 MiB memory |
| Client secrets hashed with bcrypt | PASS | `bcryptCompare` used for verification |
| Refresh tokens stored as SHA-256 hashes | PASS | Raw tokens never persisted |
| Verification tokens stored as SHA-256 hashes | PASS | Same pattern as refresh tokens |
| PKCE verification uses constant-time comparison | PASS | **Fixed:** Now uses `subtle.ConstantTimeCompare` |
| Session IDs are 256-bit random | PASS | 32 bytes from `crypto/rand` |

### A03: Injection - PASS

| Check | Status | Notes |
|-------|--------|-------|
| All SQL uses parameterized queries | PASS | No string concatenation in SQL; verified via grep |
| No command injection vectors | PASS | No `os/exec` usage |
| HTML template uses `html/template` (auto-escaping) | PASS | Login page template is auto-escaped |
| JSON responses use `encoding/json` (proper escaping) | PASS | All API responses are JSON-encoded |

### A04: Insecure Design - PASS

| Check | Status | Notes |
|-------|--------|-------|
| Authorization code is one-time use | PASS | Deleted immediately on exchange |
| Refresh token rotation with family tracking | PASS | Theft detection revokes entire family |
| PKCE required by default for clients | PASS | `PKCERequired: true` is default |
| Only S256 code challenge method supported | PASS | Plain method rejected |
| Password reset silent on unknown emails | PASS | Returns success regardless to prevent enumeration |
| Login errors don't distinguish user/password | PASS | "Invalid email or password" for all failures |

### A05: Security Misconfiguration - PASS (with fixes)

| Check | Status | Notes |
|-------|--------|-------|
| Security headers on all responses | PASS | X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| CSP on HTML pages | PASS | `default-src 'self'` policy |
| No-cache on auth endpoints | PASS | `Cache-Control: no-store` |
| Error responses don't leak internals | PASS | **Fixed:** Removed `err.Error()` and `fmt.Sprintf("%v", err)` from responses |
| seki.yaml written with restrictive permissions | PASS | **Fixed:** Changed from 0644 to 0600 |
| Private key files written with 0600 | PASS | Already correct |

### A06: Vulnerable Components - PASS

| Check | Status | Notes |
|-------|--------|-------|
| No known CVEs in dependencies | PASS | `govulncheck` clean |
| Using current versions of critical libs | PASS | golang-jwt/v5, x/crypto latest |

### A07: Authentication Failures - PASS

| Check | Status | Notes |
|-------|--------|-------|
| Brute-force protection on login | PASS | Rate limiter with configurable lockout |
| Password minimum length enforced | PASS | Minimum 8 characters |
| Password maximum length enforced | PASS | **Fixed:** Maximum 128 characters (prevents DoS via argon2) |
| Session idle timeout | PASS | Default 30 minutes |
| Session absolute timeout | PASS | Default 24 hours |
| Session cookie is HttpOnly | PASS | Set in session manager |
| Session cookie is SameSite=Lax | PASS | Default SameSite mode |
| Concurrent session limiting | PASS | Configurable; oldest sessions evicted |

### A08: Software and Data Integrity - PASS

| Check | Status | Notes |
|-------|--------|-------|
| JSON deserialization uses standard library | PASS | `encoding/json` only |
| No `unsafe` package usage | PASS | Not imported anywhere |
| Request body size limited | PASS | **Fixed:** `http.MaxBytesReader` on all POST/PUT/PATCH |
| Webhook signatures use HMAC-SHA256 | PASS | `X-Seki-Signature` header |

### A09: Security Logging and Monitoring - PASS

| Check | Status | Notes |
|-------|--------|-------|
| Audit log for auth events | PASS | `audit.Logger` with DB + stdout output |
| Event types cover critical actions | PASS | login, logout, user.created, token.issued, etc. |
| Audit log API with pagination | PASS | `/api/v1/audit-logs` endpoint |
| Prometheus metrics available | PASS | `/metrics` endpoint with request counts |

### A10: Server-Side Request Forgery - PASS

| Check | Status | Notes |
|-------|--------|-------|
| Webhook URLs from config only | PASS | Not user-controllable |
| Social login callbacks use hardcoded provider URLs | PASS | `knownProviders` map with fixed endpoints |
| No user-supplied URLs in outbound requests | PASS | All external URLs are server-configured |

---

## Issues Found and Remediated

### Critical

1. **Open redirect on logout** (`internal/oidc/login.go`)
   - `POST /logout` accepted arbitrary `redirect_uri` from form input without validation
   - **Fix:** Added `isSafeRedirect()` that validates the redirect target matches the issuer's host
   - **Test:** `TestLogout_OpenRedirectPrevention`

### High

2. **Error messages leaking internal details** (multiple files)
   - `handleListClients` used `fmt.Sprintf("failed to list clients: %v", err)` exposing raw error
   - `handleListAuditLogs` used `err.Error()` directly in response
   - `handleUserInfo` concatenated `err.Error()` into JSON string (potential JSON injection)
   - **Fix:** Replaced with generic error messages; used proper `json.NewEncoder` for structured errors
   - **Tests:** `TestErrorResponse_NoStackTraces`, `TestErrorResponse_AuditLogNoLeaks`, `TestErrorResponse_ClientListNoLeaks`

3. **PKCE verification used non-constant-time comparison** (`internal/oidc/token.go`)
   - `verifyPKCE` used `==` instead of `subtle.ConstantTimeCompare`
   - **Fix:** Changed to `subtle.ConstantTimeCompare`

### Medium

4. **No request body size limits** (all endpoints)
   - No `http.MaxBytesReader` applied, allowing arbitrarily large payloads
   - **Fix:** Added body size limiting in `SecurityHeaders` middleware for all POST/PUT/PATCH requests (64 KiB limit), plus admin API middleware
   - **Test:** `TestBodySizeLimit_OversizedPayloadRejected`

5. **No password maximum length** (`internal/authn/password/password.go`)
   - Passwords of arbitrary length accepted, enabling DoS via expensive argon2id hashing
   - **Fix:** Added 128-character maximum length check
   - **Test:** `TestValidation_Password`

6. **No redirect_uri scheme validation** (`internal/oidc/authorize.go`)
   - `javascript:`, `data:`, and `vbscript:` scheme URIs were not explicitly rejected before client registration check
   - **Fix:** Added `validate.RedirectURI()` check before client matching
   - **Test:** `TestRedirectURI_JavaScriptSchemeBlocked`

7. **Missing input validation on admin endpoints** (multiple files)
   - No length limits on display names, organization names, slugs, metadata
   - No format validation on client IDs, slugs
   - **Fix:** Created `internal/validate/` package with shared validators; applied to all admin endpoints
   - **Tests:** `TestValidation_EmailFormat`, `TestValidation_Slug`, `TestValidation_RedirectURI`, `TestValidation_MetadataSize`

8. **Config file written with permissive mode** (`cmd/seki-cli/commands.go`)
   - `seki.yaml` was written with 0644 permissions; may contain secrets
   - **Fix:** Changed to 0600

---

## Remaining Risks and Mitigations

| Risk | Severity | Mitigation |
|------|----------|------------|
| X-Forwarded-For header spoofing | Low | Configure `trusted_proxies` in production; use behind a reverse proxy that overwrites XFF |
| No per-endpoint rate limiting | Low | Global rate limiter is in place; add endpoint-specific limits if needed |
| Webhook URLs are SSRF vectors if config is compromised | Low | Config file restricted to 0600; validate webhook URLs via `validate.URL()` |
| Session cookie `Secure` flag defaults to false | Low | Set `session.cookie_secure: true` in production config |
| No TOTP brute-force protection beyond global rate limit | Low | TOTP codes expire quickly (30s window); consider adding per-user lockout |

---

## Security Configuration Recommendations

1. **Always set `rate_limit.enabled: true`** with `login_attempts_max: 5` and `lockout_duration: 15m`
2. **Configure `cors.allowed_origins`** with explicit origins; never use `*`
3. **Set `session.cookie_secure: true`** in production (requires HTTPS)
4. **Use strong API keys** (at least 32 random characters) for admin endpoints
5. **Enable TLS termination** at the reverse proxy level
6. **Set `server.trusted_proxies`** to your reverse proxy CIDR ranges
7. **Rotate signing keys** periodically using the `seki-cli generate-key` command
8. **Monitor audit logs** for `user.login.failed` events to detect credential stuffing
9. **Set `pkce_required: true`** for all public OAuth2 clients (this is the default)
10. **Run `govulncheck ./...`** in CI to catch dependency vulnerabilities early
