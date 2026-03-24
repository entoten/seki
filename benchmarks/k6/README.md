# k6 Load Tests for Seki

Load test scripts for the seki OIDC provider using [k6](https://k6.io/).

## Prerequisites

1. Install k6: https://k6.io/docs/get-started/installation/
2. Start seki locally (default `http://localhost:8080`)
3. Create a `load-test-client` with `client_credentials` grant type

## Running Tests

### Token Issuance (client_credentials)

```bash
k6 run -e BASE_URL=http://localhost:8080 \
       -e CLIENT_ID=load-test-client \
       -e CLIENT_SECRET=load-test-secret \
       benchmarks/k6/token-issuance.js
```

### Full OIDC Flow

```bash
k6 run -e BASE_URL=http://localhost:8080 \
       -e CLIENT_ID=load-test-client \
       -e CLIENT_SECRET=load-test-secret \
       benchmarks/k6/full-flow.js
```

### Quick Smoke Test

Run with fewer VUs for a quick sanity check:

```bash
k6 run --vus 5 --duration 30s \
       -e BASE_URL=http://localhost:8080 \
       -e CLIENT_ID=load-test-client \
       -e CLIENT_SECRET=load-test-secret \
       benchmarks/k6/token-issuance.js
```

## Expected Results

| Metric | Target |
|--------|--------|
| Token issuance p50 | < 5ms |
| Token issuance p99 | < 20ms |
| Discovery p50 | < 1ms |
| Discovery p99 | < 5ms |
| JWKS p50 | < 1ms |
| JWKS p99 | < 5ms |
| Introspection p50 | < 2ms |
| Introspection p99 | < 10ms |
| Success rate | > 99% |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BASE_URL` | `http://localhost:8080` | Seki server URL |
| `CLIENT_ID` | `load-test-client` | OAuth client ID |
| `CLIENT_SECRET` | `load-test-secret` | OAuth client secret |
