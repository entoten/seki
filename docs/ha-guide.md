# Seki High-Availability Deployment Guide

This guide covers running multiple Seki instances behind a load balancer for
high availability and horizontal scaling.

## Architecture

```
                    +-------------------+
                    |  Load Balancer    |
                    | (Nginx / Caddy)   |
                    +--------+----------+
                             |
              +--------------+--------------+
              |              |              |
        +-----+----+  +-----+----+  +-----+----+
        | seki :8080|  | seki :8080|  | seki :8080|
        +-----+----+  +-----+----+  +-----+----+
              |              |              |
              +--------------+--------------+
                             |
                    +--------+----------+
                    |   PostgreSQL      |
                    +-------------------+
```

All Seki instances connect to the same PostgreSQL database. Sessions, users,
clients, audit logs, and all other state are stored in the database, so any
instance can serve any request.

## Prerequisites

- **PostgreSQL** (recommended for production HA deployments)
- **Shared signing key** -- all instances must use the same key file to produce
  and verify JWTs. Mount the key file from a shared volume or secret store.
- **Shared configuration** -- all instances should use identical `seki.yaml`
  configuration (same `server.issuer`, same `signing.key_file`, etc.).

## Health Check Configuration

Seki exposes three health endpoints:

| Endpoint          | Purpose           | Behavior                                      |
|-------------------|-------------------|-----------------------------------------------|
| `GET /healthz`      | Readiness (alias) | Returns 200 if DB is reachable, 503 otherwise |
| `GET /healthz/ready` | Readiness probe   | Returns 200 if DB is reachable, 503 otherwise |
| `GET /healthz/live`  | Liveness probe    | Always returns 200 if process is running      |

### Load Balancer Health Checks

Configure your load balancer to use `/healthz/ready` for backend health checks.
This ensures traffic is only routed to instances that can reach the database.

For Kubernetes, use `/healthz/live` for the liveness probe (restart on hang) and
`/healthz/ready` for the readiness probe (remove from service on DB failure).

## Session Sharing

Sessions are stored in the database (PostgreSQL or SQLite), not in memory.
This means:

- Any instance can validate any session
- Session creation, rotation, and expiry work across instances
- No sticky sessions are required at the load balancer

## Trusted Proxies

When running behind a reverse proxy, configure `server.trusted_proxies` so Seki
correctly reads the client IP from `X-Forwarded-For` headers:

```yaml
server:
  address: ":8080"
  issuer: "https://auth.example.com"
  trusted_proxies:
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"
```

## Docker Compose Example

```yaml
version: "3.9"

services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: seki
      POSTGRES_USER: seki
      POSTGRES_PASSWORD: secretpassword
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U seki"]
      interval: 5s
      timeout: 3s
      retries: 5

  seki:
    image: ghcr.io/monet/seki:latest
    deploy:
      replicas: 3
    volumes:
      - ./seki.yaml:/etc/seki/seki.yaml:ro
      - ./signing-key.pem:/etc/seki/signing-key.pem:ro
    environment:
      SEKI_CONFIG: /etc/seki/seki.yaml
    depends_on:
      postgres:
        condition: service_healthy

  nginx:
    image: nginx:alpine
    ports:
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./certs:/etc/nginx/certs:ro
    depends_on:
      - seki

volumes:
  pgdata:
```

## Nginx Reverse Proxy Example

```nginx
upstream seki_backend {
    least_conn;
    server seki-1:8080;
    server seki-2:8080;
    server seki-3:8080;
}

server {
    listen 443 ssl;
    server_name auth.example.com;

    ssl_certificate     /etc/nginx/certs/cert.pem;
    ssl_certificate_key /etc/nginx/certs/key.pem;

    location / {
        proxy_pass http://seki_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /healthz {
        proxy_pass http://seki_backend;
        access_log off;
    }
}
```

## Caddy Reverse Proxy Example

```
auth.example.com {
    reverse_proxy seki-1:8080 seki-2:8080 seki-3:8080 {
        lb_policy least_conn
        health_uri /healthz/ready
        health_interval 5s
    }
}
```

## Key Management

All instances **must** share the same signing key to produce and verify JWTs.

Options:
- Mount a shared volume containing the key file
- Use a Kubernetes Secret mounted as a file
- Use a secrets manager (Vault, AWS Secrets Manager) and write the key to a
  shared path at startup

```yaml
signing:
  algorithm: "RS256"
  key_file: "/etc/seki/signing-key.pem"
```

## What Works in HA

| Feature                    | HA-Ready | Notes                                  |
|----------------------------|----------|----------------------------------------|
| Stateless HTTP handling    | Yes      | No in-memory request state             |
| DB-backed sessions         | Yes      | Any instance can serve any session     |
| Shared signing keys        | Yes      | All instances sign/verify identically  |
| User/client management     | Yes      | All CRUD is DB-backed                  |
| Audit logging              | Yes      | Written to shared DB                   |
| OIDC/OAuth2 flows          | Yes      | Auth codes and tokens are DB-backed    |

## What Does Not Work in HA (per-instance state)

| Feature                    | Issue                                   | Workaround                |
|----------------------------|-----------------------------------------|---------------------------|
| In-memory rate limiter     | Each instance has its own counters      | Use Redis (planned v0.4)  |
| WebAuthn challenge store   | Challenges stored in memory per-instance| Use Redis (planned v0.4)  |

### Impact

- **Rate limiter**: Limits are enforced per-instance, so a user could hit
  `N * limit` requests across `N` instances. For most deployments this is
  acceptable; for strict rate limiting, wait for Redis support.
- **WebAuthn challenges**: A passkey registration/authentication flow must
  complete on the same instance that started it. Use sticky sessions at the LB
  for `/authn/passkey/*` routes, or wait for Redis-backed challenge storage.

## Recommendations for v0.4

- Redis-backed rate limiter for globally consistent rate limiting
- Redis-backed WebAuthn challenge store for stateless passkey flows
- Prometheus metrics aggregation via a central scraper (already works --
  each instance exposes `/metrics`)

## Session Management in HA

Configure maximum concurrent sessions per user:

```yaml
session:
  max_concurrent_sessions: 5  # 0 = unlimited
```

When the limit is reached, the oldest session is automatically evicted to make
room for new logins. This works correctly across instances because session
counting and eviction are performed against the shared database.
