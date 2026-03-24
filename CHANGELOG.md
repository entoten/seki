# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## v0.1.0 (Unreleased)

### Added

- OIDC Provider (Authorization Code + PKCE, Client Credentials, Refresh Token)
- OIDC Discovery (`/.well-known/openid-configuration`) and JWKS (`/.well-known/jwks.json`)
- Passkey (WebAuthn) registration and authentication with discoverable credentials
- Passkey credential lifecycle management (list, rename, delete, inactive detection)
- TOTP setup, verification, and recovery codes
- Password authentication (opt-in, not enabled by default)
- Social Login (Google, GitHub) via OAuth2 federation
- User CRUD and search via Admin API
- Organization / Tenant management with domain association
- Role-based access control (RBAC) with customizable permissions per organization
- Organization membership management (add, remove, update role)
- Admin REST API with API Key authentication (`/api/v1/`)
- Audit logging (DB + stdout JSON) with cursor-based pagination
- Webhook emitter with HMAC-SHA256 signatures and configurable event subscriptions
- Session management (DB-persistent, idle + absolute timeout)
- Login and logout flows with session integration
- YAML configuration with environment variable expansion
- Docker and docker-compose support with PostgreSQL
- PostgreSQL and SQLite database backends
- Health check endpoint (`/healthz`)
- RFC 7807 Problem Details error responses
- Ed25519 (EdDSA) token signing with RSA support
