# Seki Performance Benchmarks

## Performance Targets

| Operation | p50 | p99 | Target RPS |
|-----------|-----|-----|------------|
| Token (client_credentials) | <5ms | <20ms | 10,000 |
| Token (auth_code) | <10ms | <50ms | 5,000 |
| Introspection | <2ms | <10ms | 20,000 |
| Discovery | <1ms | <5ms | 50,000 |
| JWKS | <1ms | <5ms | 50,000 |

## Go Benchmark Results

Measured on AMD Ryzen 5 7430U, linux/amd64, Go 1.26.1, SQLite in-memory storage.

### OIDC Endpoints

```
BenchmarkTokenEndpoint_ClientCredentials-12      1377      851261 ns/op     21589 B/op    210 allocs/op
BenchmarkTokenEndpoint_AuthorizationCode-12      1218      977982 ns/op     32918 B/op    448 allocs/op
BenchmarkIntrospect-12                           1364      881975 ns/op     20953 B/op    223 allocs/op
BenchmarkDiscovery-12                          129483       10051 ns/op     10907 B/op     96 allocs/op
BenchmarkJWKS-12                               269779        4320 ns/op      7635 B/op     45 allocs/op
```

Summary (per-operation latency):

| Operation | Latency (ns/op) | Approx. ms |
|-----------|-----------------|------------|
| Token (client_credentials) | 851,261 | ~0.85 |
| Token (auth_code) | 977,982 | ~0.98 |
| Introspection | 881,975 | ~0.88 |
| Discovery | 10,051 | ~0.01 |
| JWKS | 4,320 | ~0.004 |

Note: Token and introspection benchmarks include bcrypt client secret verification
(cost=4 for tests). Production bcrypt cost (10+) will increase these times. The
benchmarks use in-memory SQLite; production latencies with PostgreSQL will differ.

### Cryptographic Operations

```
BenchmarkEd25519Sign-12        49813       23599 ns/op      3506 B/op     45 allocs/op
BenchmarkEd25519Verify-12      23659       50532 ns/op      3144 B/op     66 allocs/op
BenchmarkArgon2idHash-12          62    29612911 ns/op  67117243 B/op     48 allocs/op
BenchmarkBcryptHash-12            22    49960701 ns/op      5294 B/op     10 allocs/op
```

Summary:

| Operation | Latency (ns/op) | Approx. ms | Throughput |
|-----------|-----------------|------------|------------|
| Ed25519 Sign | 23,599 | ~0.024 | ~42,000/sec |
| Ed25519 Verify | 50,532 | ~0.051 | ~19,000/sec |
| Argon2id Hash (64 MiB) | 29,612,911 | ~30 | ~33/sec |
| Bcrypt Hash (cost=10) | 49,960,701 | ~50 | ~20/sec |

## Running Benchmarks

### Go Benchmarks

```bash
# OIDC endpoint benchmarks
go test -bench=. -benchmem ./internal/oidc/

# Cryptographic benchmarks
go test -bench=. -benchmem ./internal/crypto/

# All benchmarks
go test -bench=. -benchmem ./internal/oidc/ ./internal/crypto/
```

### k6 Load Tests

See [benchmarks/k6/README.md](../benchmarks/k6/README.md) for instructions on
running k6 load tests against a live seki instance.

```bash
# Quick smoke test
k6 run --vus 5 --duration 30s benchmarks/k6/token-issuance.js

# Full ramp-up test
k6 run benchmarks/k6/token-issuance.js
```

## Fuzz Testing

Fuzz tests run as part of the standard test suite (seed corpus only) and can be
extended with continuous fuzzing:

```bash
# Run a specific fuzz test for 30 seconds
go test -fuzz=FuzzSCIMFilterParsing -fuzztime=30s ./internal/scim/
go test -fuzz=FuzzPKCEVerification -fuzztime=30s ./internal/oidc/
go test -fuzz=FuzzPasswordHashVerify -fuzztime=30s ./internal/crypto/
go test -fuzz=FuzzEmailValidation -fuzztime=30s ./internal/validate/
```
