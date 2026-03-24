# Contributing to seki

Thank you for your interest in contributing to seki!

## Development Setup

```bash
# Clone
git clone https://github.com/entoten/seki.git
cd seki

# Build
go build ./...

# Test
go test ./...

# Lint
golangci-lint run ./...

# Run (dev mode, SQLite)
cp seki.yaml.example seki.yaml
go run ./cmd/seki
```

## Development Workflow

1. Fork the repository on GitHub
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Run tests: `go test ./...`
5. Run linter: `golangci-lint run ./...`
6. Commit with a descriptive message
7. Push and create a Pull Request

## Code Standards

- Go 1.26+
- All code must pass `golangci-lint`
- All code must pass `gosec`
- Test coverage should not decrease
- Follow existing code patterns and conventions

## What We Accept

- Bug fixes
- Performance improvements
- Documentation improvements
- New authentication methods
- Security enhancements

## What We Don't Accept

- SAML support (intentional scope decision)
- Features that add significant complexity without clear benefit
- Changes that break backward compatibility without discussion

## Reporting Security Issues

**Do not open a public issue for security vulnerabilities.**

Email: security@entoten.dev (or use GitHub's private vulnerability reporting)

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
