# Stage 1: Build
FROM golang:1.26-alpine AS builder

RUN apk add --no-cache git

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-s -w -X main.version=$(cat VERSION 2>/dev/null || echo 0.1.0-dev)" \
    -o /bin/seki ./cmd/seki

# Stage 2: Runtime
FROM alpine:3.21

LABEL org.opencontainers.image.title="seki" \
      org.opencontainers.image.description="Lightweight OIDC identity server with passkey, TOTP, password, and social login" \
      org.opencontainers.image.url="https://github.com/Monet/seki" \
      org.opencontainers.image.source="https://github.com/Monet/seki" \
      org.opencontainers.image.vendor="Monet" \
      org.opencontainers.image.licenses="MIT"

RUN apk add --no-cache ca-certificates curl \
    && addgroup -S seki && adduser -S seki -G seki

WORKDIR /app

# Create directories for data and keys (owned by seki user).
RUN mkdir -p /app/data /app/keys && chown -R seki:seki /app

COPY --from=builder /bin/seki /app/seki
COPY --from=builder /src/seki.yaml.example /app/seki.yaml.example

# The binary embeds migrations (via storage packages) and web templates
# (via go:embed), so no separate copy of those directories is needed.

RUN chown seki:seki /app/seki

USER seki

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -sf http://localhost:8080/healthz || exit 1

ENTRYPOINT ["/app/seki"]
CMD ["-config", "/app/seki.yaml"]
