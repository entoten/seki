package oidc_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/entoten/seki/internal/crypto"
	"github.com/entoten/seki/internal/oidc"
)

func newTestSigner(t *testing.T) crypto.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	return crypto.NewEd25519SignerFromKey(priv, "test-key-1", "https://auth.example.com", time.Hour)
}

func TestDiscoveryEndpoint(t *testing.T) {
	signer := newTestSigner(t)
	provider := oidc.NewProvider("https://auth.example.com", signer, nil)

	mux := http.NewServeMux()
	provider.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Fatalf("expected Content-Type application/json, got %s", ct)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding response: %v", err)
	}

	// Check issuer matches.
	if body["issuer"] != "https://auth.example.com" {
		t.Errorf("issuer = %v, want https://auth.example.com", body["issuer"])
	}

	// Check all required fields are present.
	requiredFields := []string{
		"issuer",
		"authorization_endpoint",
		"token_endpoint",
		"userinfo_endpoint",
		"jwks_uri",
		"scopes_supported",
		"response_types_supported",
		"grant_types_supported",
		"subject_types_supported",
		"id_token_signing_alg_values_supported",
		"token_endpoint_auth_methods_supported",
		"code_challenge_methods_supported",
	}
	for _, field := range requiredFields {
		if _, ok := body[field]; !ok {
			t.Errorf("missing required field: %s", field)
		}
	}

	// Check specific endpoint values.
	if body["authorization_endpoint"] != "https://auth.example.com/authorize" {
		t.Errorf("authorization_endpoint = %v", body["authorization_endpoint"])
	}
	if body["token_endpoint"] != "https://auth.example.com/token" {
		t.Errorf("token_endpoint = %v", body["token_endpoint"])
	}
	if body["userinfo_endpoint"] != "https://auth.example.com/userinfo" {
		t.Errorf("userinfo_endpoint = %v", body["userinfo_endpoint"])
	}
	if body["jwks_uri"] != "https://auth.example.com/.well-known/jwks.json" {
		t.Errorf("jwks_uri = %v", body["jwks_uri"])
	}

	// Check signing algorithm.
	algs, ok := body["id_token_signing_alg_values_supported"].([]interface{})
	if !ok || len(algs) == 0 {
		t.Fatal("id_token_signing_alg_values_supported missing or empty")
	}
	if algs[0] != "EdDSA" {
		t.Errorf("signing alg = %v, want EdDSA", algs[0])
	}
}

func TestJWKSEndpoint(t *testing.T) {
	signer := newTestSigner(t)
	provider := oidc.NewProvider("https://auth.example.com", signer, nil)

	mux := http.NewServeMux()
	provider.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Fatalf("expected Content-Type application/json, got %s", ct)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding response: %v", err)
	}

	keys, ok := body["keys"].([]interface{})
	if !ok {
		t.Fatal("keys field missing or not an array")
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}

	key, ok := keys[0].(map[string]interface{})
	if !ok {
		t.Fatal("key is not an object")
	}

	// Verify key fields.
	if key["kty"] != "OKP" {
		t.Errorf("kty = %v, want OKP", key["kty"])
	}
	if key["crv"] != "Ed25519" {
		t.Errorf("crv = %v, want Ed25519", key["crv"])
	}
	if key["alg"] != "EdDSA" {
		t.Errorf("alg = %v, want EdDSA", key["alg"])
	}
	if key["use"] != "sig" {
		t.Errorf("use = %v, want sig", key["use"])
	}
	if key["kid"] != "test-key-1" {
		t.Errorf("kid = %v, want test-key-1", key["kid"])
	}
	if key["x"] == nil || key["x"] == "" {
		t.Error("x (public key) is missing or empty")
	}
}

func TestJWKSEndpoint_CacheControl(t *testing.T) {
	signer := newTestSigner(t)
	provider := oidc.NewProvider("https://auth.example.com", signer, nil)

	mux := http.NewServeMux()
	provider.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	cc := rec.Header().Get("Cache-Control")
	if cc != "public, max-age=900" {
		t.Errorf("Cache-Control = %q, want %q", cc, "public, max-age=900")
	}
}

func TestJWKSEndpoint_MultipleKeys(t *testing.T) {
	_, priv1, _ := ed25519.GenerateKey(rand.Reader)
	_, priv2, _ := ed25519.GenerateKey(rand.Reader)
	_, priv3, _ := ed25519.GenerateKey(rand.Reader)

	s1 := crypto.NewEd25519SignerFromKey(priv1, "kid-current", "https://auth.example.com", time.Hour)
	s2 := crypto.NewEd25519SignerFromKey(priv2, "kid-old-1", "https://auth.example.com", time.Hour)
	s3 := crypto.NewEd25519SignerFromKey(priv3, "kid-old-2", "https://auth.example.com", time.Hour)

	ks := crypto.NewKeySet(s1, s2, s3)
	provider := oidc.NewProvider("https://auth.example.com", ks, nil)

	mux := http.NewServeMux()
	provider.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding response: %v", err)
	}

	keys, ok := body["keys"].([]interface{})
	if !ok {
		t.Fatal("keys field missing or not an array")
	}
	if len(keys) != 3 {
		t.Fatalf("expected 3 keys, got %d", len(keys))
	}

	// Verify all kids are present and unique.
	kids := map[string]bool{}
	for _, k := range keys {
		keyMap := k.(map[string]interface{})
		kid := keyMap["kid"].(string)
		if kids[kid] {
			t.Errorf("duplicate kid: %s", kid)
		}
		kids[kid] = true
	}

	expectedKids := []string{"kid-current", "kid-old-1", "kid-old-2"}
	for _, ek := range expectedKids {
		if !kids[ek] {
			t.Errorf("missing expected kid: %s", ek)
		}
	}
}
