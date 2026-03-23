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
FROM alpine:latest

RUN apk add --no-cache ca-certificates curl \
    && addgroup -S seki && adduser -S seki -G seki

WORKDIR /app

COPY --from=builder /bin/seki /app/seki
COPY --from=builder /src/migrations /app/migrations
COPY --from=builder /src/seki.yaml.example /app/seki.yaml.example

RUN chown -R seki:seki /app

USER seki

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/healthz || exit 1

ENTRYPOINT ["/app/seki"]
CMD ["-config", "/app/seki.yaml"]
