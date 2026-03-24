package oidc_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/entoten/seki/internal/storage"
	"github.com/golang-jwt/jwt/v5"

	_ "github.com/entoten/seki/internal/storage/sqlite"
)

// setupPrivateKeyJWTClient creates a client configured for private_key_jwt
// and returns the test server serving its JWKS and the Ed25519 private key.
func setupPrivateKeyJWTClient(t *testing.T, store storage.Storage) (*httptest.Server, ed25519.PrivateKey) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	// Serve a JWKS endpoint with the public key.
	jwks := map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "OKP",
				"crv": "Ed25519",
				"x":   base64.RawURLEncoding.EncodeToString(pub),
			},
		},
	}
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	t.Cleanup(jwksServer.Close)

	now := time.Now().UTC()
	err = store.CreateClient(context.Background(), &storage.Client{
		ID:                      "pkj-client",
		Name:                    "Private Key JWT Client",
		SecretHash:              "",
		RedirectURIs:            []string{"https://app.example.com/callback"},
		GrantTypes:              []string{"authorization_code", "client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"},
		Scopes:                  []string{"openid", "profile"},
		PKCERequired:            false,
		JWKsURI:                 jwksServer.URL,
		TokenEndpointAuthMethod: "private_key_jwt",
		CreatedAt:               now,
		UpdatedAt:               now,
	})
	if err != nil {
		t.Fatalf("create pkj client: %v", err)
	}

	return jwksServer, priv
}

// signClientAssertion creates a signed JWT client assertion.
func signClientAssertion(t *testing.T, priv ed25519.PrivateKey, clientID, audience string, expTime time.Time) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss": clientID,
		"sub": clientID,
		"aud": audience,
		"exp": expTime.Unix(),
		"iat": time.Now().Unix(),
		"jti": "test-jti-" + time.Now().String(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	signed, err := token.SignedString(priv)
	if err != nil {
		t.Fatalf("sign assertion: %v", err)
	}
	return signed
}

func TestPrivateKeyJWT_Success(t *testing.T) {
	h := newTokenHarness(t)
	_, priv := setupPrivateKeyJWTClient(t, h.store)

	// Create an auth code for the pkj-client.
	verifier := "pkj-verifier-value"
	challenge := computeS256Challenge(verifier)
	h.createAuthCode(t, "pkj-code", "pkj-client", "user-1",
		"https://app.example.com/callback", challenge, "nonce-pkj",
		[]string{"openid", "profile"}, time.Now().Add(10*time.Minute))

	assertion := signClientAssertion(t, priv, "pkj-client", "https://auth.example.com/token", time.Now().Add(5*time.Minute))

	params := url.Values{
		"grant_type":            {"authorization_code"},
		"code":                  {"pkj-code"},
		"redirect_uri":         {"https://app.example.com/callback"},
		"code_verifier":        {verifier},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {assertion},
	}

	resp := h.doTokenRequest(t, params)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body := decodeTokenResponse(t, resp)
		t.Fatalf("expected 200, got %d: %v", resp.StatusCode, body)
	}
	body := decodeTokenResponse(t, resp)
	if body["access_token"] == nil || body["access_token"] == "" {
		t.Error("missing access_token")
	}
}

func TestPrivateKeyJWT_InvalidSignature(t *testing.T) {
	h := newTokenHarness(t)
	_ = setupPrivateKeyJWTClient_NoReturn(t, h.store) // create client with its JWKS

	// Sign with a DIFFERENT key than the one registered.
	_, wrongPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	assertion := signClientAssertion(t, wrongPriv, "pkj-client", "https://auth.example.com/token", time.Now().Add(5*time.Minute))

	params := url.Values{
		"grant_type":            {"authorization_code"},
		"code":                  {"some-code"},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {assertion},
	}

	resp := h.doTokenRequest(t, params)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		body := decodeTokenResponse(t, resp)
		t.Fatalf("expected 401, got %d: %v", resp.StatusCode, body)
	}
	body := decodeTokenResponse(t, resp)
	if body["error"] != "invalid_client" {
		t.Errorf("error = %v, want invalid_client", body["error"])
	}
}

func TestPrivateKeyJWT_WrongAudience(t *testing.T) {
	h := newTokenHarness(t)
	_, priv := setupPrivateKeyJWTClient(t, h.store)

	// Sign with the wrong audience.
	assertion := signClientAssertion(t, priv, "pkj-client", "https://wrong-issuer.example.com/token", time.Now().Add(5*time.Minute))

	params := url.Values{
		"grant_type":            {"authorization_code"},
		"code":                  {"some-code"},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {assertion},
	}

	resp := h.doTokenRequest(t, params)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		body := decodeTokenResponse(t, resp)
		t.Fatalf("expected 401, got %d: %v", resp.StatusCode, body)
	}
	body := decodeTokenResponse(t, resp)
	if body["error"] != "invalid_client" {
		t.Errorf("error = %v, want invalid_client", body["error"])
	}
}

func TestPrivateKeyJWT_ExpiredAssertion(t *testing.T) {
	h := newTokenHarness(t)
	_, priv := setupPrivateKeyJWTClient(t, h.store)

	// Sign with an already-expired time.
	assertion := signClientAssertion(t, priv, "pkj-client", "https://auth.example.com/token", time.Now().Add(-5*time.Minute))

	params := url.Values{
		"grant_type":            {"authorization_code"},
		"code":                  {"some-code"},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {assertion},
	}

	resp := h.doTokenRequest(t, params)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		body := decodeTokenResponse(t, resp)
		t.Fatalf("expected 401, got %d: %v", resp.StatusCode, body)
	}
	body := decodeTokenResponse(t, resp)
	if body["error"] != "invalid_client" {
		t.Errorf("error = %v, want invalid_client", body["error"])
	}
}

// setupPrivateKeyJWTClient_NoReturn is like setupPrivateKeyJWTClient but doesn't return the server/key.
// It's used when we need the client registered but will use a different key for testing.
func setupPrivateKeyJWTClient_NoReturn(t *testing.T, store storage.Storage) *httptest.Server {
	t.Helper()
	srv, _ := setupPrivateKeyJWTClient(t, store)
	return srv
}

// TestPrivateKeyJWT_ES256 tests authentication using ES256 (ECDSA P-256).
func TestPrivateKeyJWT_ES256(t *testing.T) {
	h := newTokenHarness(t)

	// Generate an ECDSA P-256 key pair.
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Build JWKS with the EC public key.
	xBytes := ecPriv.PublicKey.X.Bytes()
	yBytes := ecPriv.PublicKey.Y.Bytes()
	// Pad to 32 bytes for P-256.
	for len(xBytes) < 32 {
		xBytes = append([]byte{0}, xBytes...)
	}
	for len(yBytes) < 32 {
		yBytes = append([]byte{0}, yBytes...)
	}

	jwks := map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "EC",
				"crv": "P-256",
				"x":   base64.RawURLEncoding.EncodeToString(xBytes),
				"y":   base64.RawURLEncoding.EncodeToString(yBytes),
			},
		},
	}
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	t.Cleanup(jwksServer.Close)

	now := time.Now().UTC()
	err = h.store.CreateClient(context.Background(), &storage.Client{
		ID:                      "ec-pkj-client",
		Name:                    "EC PKJ Client",
		RedirectURIs:            []string{"https://app.example.com/callback"},
		GrantTypes:              []string{"authorization_code"},
		Scopes:                  []string{"openid"},
		JWKsURI:                 jwksServer.URL,
		TokenEndpointAuthMethod: "private_key_jwt",
		CreatedAt:               now,
		UpdatedAt:               now,
	})
	if err != nil {
		t.Fatalf("create ec client: %v", err)
	}

	// Create auth code.
	verifier := "ec-pkj-verifier"
	challenge := computeS256Challenge(verifier)
	h.createAuthCode(t, "ec-pkj-code", "ec-pkj-client", "user-1",
		"https://app.example.com/callback", challenge, "",
		[]string{"openid"}, time.Now().Add(10*time.Minute))

	// Sign assertion with ES256.
	claims := jwt.MapClaims{
		"iss": "ec-pkj-client",
		"sub": "ec-pkj-client",
		"aud": "https://auth.example.com/token",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
		"iat": time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	assertion, err := token.SignedString(ecPriv)
	if err != nil {
		t.Fatal(err)
	}

	params := url.Values{
		"grant_type":            {"authorization_code"},
		"code":                  {"ec-pkj-code"},
		"redirect_uri":         {"https://app.example.com/callback"},
		"code_verifier":        {verifier},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {assertion},
	}

	resp := h.doTokenRequest(t, params)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body := decodeTokenResponse(t, resp)
		t.Fatalf("expected 200, got %d: %v", resp.StatusCode, body)
	}
	body := decodeTokenResponse(t, resp)
	if body["access_token"] == nil || body["access_token"] == "" {
		t.Error("missing access_token")
	}
}

// Suppress unused import warnings.
var _ = sha256.Sum256
var _ = big.NewInt
var _ = strings.Fields
