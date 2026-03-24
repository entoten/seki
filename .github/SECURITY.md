# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.x     | :white_check_mark: |
| 1.x     | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Please report security vulnerabilities through GitHub's private vulnerability reporting feature, or email security@entoten.dev.

We will acknowledge receipt within 48 hours and provide a detailed response within 7 days.

## Security Measures

seki is built with security as a core concern:

- OWASP Top 10 audited (see docs/security-audit.md)
- All SQL queries use parameterized placeholders
- Passwords hashed with argon2id
- Tokens stored as SHA-256 hashes
- PKCE required for public clients (S256 only)
- Refresh token rotation with theft detection
- Rate limiting and brute-force protection
- Security headers (CSP, X-Frame-Options, etc.)
- Constant-time comparison for secrets
