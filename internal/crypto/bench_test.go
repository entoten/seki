package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

// BenchmarkEd25519Sign benchmarks Ed25519 JWT signing.
func BenchmarkEd25519Sign(b *testing.B) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatalf("generate key: %v", err)
	}

	signer := NewEd25519SignerFromKey(priv, "bench-key", "https://auth.example.com", time.Hour)

	claims := map[string]interface{}{
		"sub":   "user-123",
		"aud":   "client-456",
		"scope": "openid profile email",
		"typ":   "access_token",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		_, err := signer.Sign(claims)
		if err != nil {
			b.Fatalf("sign: %v", err)
		}
	}
}

// BenchmarkEd25519Verify benchmarks Ed25519 JWT verification.
func BenchmarkEd25519Verify(b *testing.B) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatalf("generate key: %v", err)
	}

	signer := NewEd25519SignerFromKey(priv, "bench-key", "https://auth.example.com", time.Hour)

	token, err := signer.Sign(map[string]interface{}{
		"sub":   "user-123",
		"aud":   "client-456",
		"scope": "openid profile email",
		"typ":   "access_token",
	})
	if err != nil {
		b.Fatalf("sign: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		_, err := signer.Verify(token)
		if err != nil {
			b.Fatalf("verify: %v", err)
		}
	}
}

// BenchmarkArgon2idHash benchmarks Argon2id password hashing.
func BenchmarkArgon2idHash(b *testing.B) {
	hasher := NewArgon2idHasher()

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		_, err := hasher.Hash("benchmark-password-123!")
		if err != nil {
			b.Fatalf("hash: %v", err)
		}
	}
}

// BenchmarkBcryptHash benchmarks bcrypt password hashing with default cost.
func BenchmarkBcryptHash(b *testing.B) {
	hasher := NewBcryptHasher(10) // default cost

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		_, err := hasher.Hash("benchmark-password-123!")
		if err != nil {
			b.Fatalf("hash: %v", err)
		}
	}
}
