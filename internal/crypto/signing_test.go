package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewEd25519Signer_GeneratesKey(t *testing.T) {
	s, err := NewEd25519Signer(Ed25519SignerOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.Algorithm() != "EdDSA" {
		t.Errorf("expected algorithm EdDSA, got %s", s.Algorithm())
	}
	if s.KeyID() != "seki-ed25519-1" {
		t.Errorf("expected default key ID, got %s", s.KeyID())
	}
}

func TestNewEd25519Signer_CustomKeyID(t *testing.T) {
	s, err := NewEd25519Signer(Ed25519SignerOptions{
		KeyID: "my-key",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.KeyID() != "my-key" {
		t.Errorf("expected key ID my-key, got %s", s.KeyID())
	}
}

func TestSignAndVerify_RoundTrip(t *testing.T) {
	s, err := NewEd25519Signer(Ed25519SignerOptions{
		Issuer:   "test-issuer",
		TokenTTL: 5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	claims := map[string]interface{}{
		"sub":   "user-123",
		"email": "user@example.com",
	}

	token, err := s.Sign(claims)
	if err != nil {
		t.Fatalf("sign error: %v", err)
	}

	if token == "" {
		t.Fatal("expected non-empty token")
	}

	result, err := s.Verify(token)
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}

	if result["sub"] != "user-123" {
		t.Errorf("expected sub user-123, got %v", result["sub"])
	}
	if result["email"] != "user@example.com" {
		t.Errorf("expected email user@example.com, got %v", result["email"])
	}
	if result["iss"] != "test-issuer" {
		t.Errorf("expected iss test-issuer, got %v", result["iss"])
	}
}

func TestVerify_InvalidToken(t *testing.T) {
	s, err := NewEd25519Signer(Ed25519SignerOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = s.Verify("not.a.valid.token")
	if err == nil {
		t.Error("expected error for invalid token")
	}
}

func TestVerify_WrongKey(t *testing.T) {
	s1, err := NewEd25519Signer(Ed25519SignerOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	s2, err := NewEd25519Signer(Ed25519SignerOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	token, err := s1.Sign(map[string]interface{}{"sub": "user-1"})
	if err != nil {
		t.Fatalf("sign error: %v", err)
	}

	_, err = s2.Verify(token)
	if err == nil {
		t.Error("expected error when verifying with different key")
	}
}

func TestVerify_ExpiredToken(t *testing.T) {
	s, err := NewEd25519Signer(Ed25519SignerOptions{
		TokenTTL: 1 * time.Second,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Create a token with an already-expired exp claim.
	claims := map[string]interface{}{
		"sub": "user-1",
		"exp": time.Now().Add(-1 * time.Hour).Unix(),
	}
	token, err := s.Sign(claims)
	if err != nil {
		t.Fatalf("sign error: %v", err)
	}

	_, err = s.Verify(token)
	if err == nil {
		t.Error("expected error for expired token")
	}
}

func TestPublicKeyJWK(t *testing.T) {
	s, err := NewEd25519Signer(Ed25519SignerOptions{
		KeyID: "test-key-1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	jwk := s.PublicKeyJWK()

	if jwk["kty"] != "OKP" {
		t.Errorf("expected kty OKP, got %v", jwk["kty"])
	}
	if jwk["crv"] != "Ed25519" {
		t.Errorf("expected crv Ed25519, got %v", jwk["crv"])
	}
	if jwk["alg"] != "EdDSA" {
		t.Errorf("expected alg EdDSA, got %v", jwk["alg"])
	}
	if jwk["use"] != "sig" {
		t.Errorf("expected use sig, got %v", jwk["use"])
	}
	if jwk["kid"] != "test-key-1" {
		t.Errorf("expected kid test-key-1, got %v", jwk["kid"])
	}

	// Verify the "x" field is valid base64url-encoded 32-byte public key.
	xStr, ok := jwk["x"].(string)
	if !ok {
		t.Fatal("expected x to be a string")
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(xStr)
	if err != nil {
		t.Fatalf("decoding x: %v", err)
	}
	if len(xBytes) != ed25519.PublicKeySize {
		t.Errorf("expected public key size %d, got %d", ed25519.PublicKeySize, len(xBytes))
	}
}

func TestKeyPersistence(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "test-key.pem")

	// Create signer; key file does not exist, so it should be generated.
	s1, err := NewEd25519Signer(Ed25519SignerOptions{
		KeyFile: keyFile,
		KeyID:   "persist-key",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the file was created.
	if _, err := os.Stat(keyFile); err != nil {
		t.Fatalf("key file not created: %v", err)
	}

	// Create a second signer from the same file.
	s2, err := NewEd25519Signer(Ed25519SignerOptions{
		KeyFile: keyFile,
		KeyID:   "persist-key",
	})
	if err != nil {
		t.Fatalf("unexpected error loading key: %v", err)
	}

	// Sign with s1, verify with s2.
	token, err := s1.Sign(map[string]interface{}{"sub": "user-persist"})
	if err != nil {
		t.Fatalf("sign error: %v", err)
	}

	claims, err := s2.Verify(token)
	if err != nil {
		t.Fatalf("verify error (should work with same key): %v", err)
	}
	if claims["sub"] != "user-persist" {
		t.Errorf("expected sub user-persist, got %v", claims["sub"])
	}
}

func TestNewEd25519SignerFromKey(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	_ = pub

	s := NewEd25519SignerFromKey(priv, "from-key", "test", time.Minute)

	token, err := s.Sign(map[string]interface{}{"sub": "direct"})
	if err != nil {
		t.Fatalf("sign error: %v", err)
	}

	claims, err := s.Verify(token)
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if claims["sub"] != "direct" {
		t.Errorf("expected sub direct, got %v", claims["sub"])
	}
}
