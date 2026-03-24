package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

// FuzzPasswordHashVerify fuzzes password verification with random inputs.
// The main assertion is that Verify never panics on any input.
func FuzzPasswordHashVerify(f *testing.F) {
	// Generate a valid bcrypt hash for seeding.
	bcryptHasher := NewBcryptHasher(4) // low cost for fuzz speed
	validHash, _ := bcryptHasher.Hash("correctpassword")

	f.Add("correctpassword", validHash)
	f.Add("wrongpassword", validHash)
	f.Add("", validHash)
	f.Add("password", "")
	f.Add("", "")
	f.Add("password", "$2a$10$invalidhashvalue")
	f.Add("password", "not-a-hash-at-all")
	f.Add(strings.Repeat("a", 200), validHash)
	f.Add("password", "$argon2id$v=19$m=65536,t=1,p=4$c29tZXNhbHQ$somehash")
	f.Add("\x00\x01\x02", validHash)

	f.Fuzz(func(t *testing.T, password, hash string) {
		// Bcrypt hasher should never panic.
		hasher := NewBcryptHasher(4)
		_ = hasher.Verify(password, hash)

		// Argon2id hasher should never panic.
		argonHasher := NewArgon2idHasher()
		_ = argonHasher.Verify(password, hash)
	})
}

// FuzzJWTVerify fuzzes JWT verification with random token strings.
// The main assertion is that Verify never panics on any input.
func FuzzJWTVerify(f *testing.F) {
	// Create a signer for generating valid tokens.
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer := NewEd25519SignerFromKey(priv, "test-key", "test-issuer", time.Hour)

	// Generate a valid token for seeding.
	validToken, _ := signer.Sign(map[string]interface{}{
		"sub": "user-123",
	})

	f.Add(validToken)
	f.Add("")
	f.Add("not-a-jwt")
	f.Add("header.payload.signature")
	f.Add("eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiIxMjMifQ.invalidsig")
	f.Add(strings.Repeat("a", 10000))
	f.Add("eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiIxMjMifQ.")
	f.Add("\x00\x01\x02\x03")
	f.Add("a]b[c{d}e")
	f.Add("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjMifQ.fake")

	f.Fuzz(func(t *testing.T, tokenString string) {
		// Should never panic regardless of input.
		_, _ = signer.Verify(tokenString)
	})
}
