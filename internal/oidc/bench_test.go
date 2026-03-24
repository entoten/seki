package oidc_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/entoten/seki/internal/crypto"
	"github.com/entoten/seki/internal/oidc"
	"github.com/entoten/seki/internal/storage"

	_ "github.com/entoten/seki/internal/storage/sqlite"
)

// benchHarness sets up a Provider with in-memory storage for benchmarks.
type benchHarness struct {
	store    storage.Storage
	provider *oidc.Provider
	mux      *http.ServeMux
	signer   crypto.Signer
}

func newBenchHarness(b *testing.B) *benchHarness {
	b.Helper()

	store, err := storage.New(storage.TestDatabaseConfig())
	if err != nil {
		b.Fatalf("open storage: %v", err)
	}
	if err := store.Migrate(); err != nil {
		b.Fatalf("migrate: %v", err)
	}
	b.Cleanup(func() { store.Close() })

	ctx := context.Background()
	now := time.Now().UTC()

	// Create a test user.
	err = store.CreateUser(ctx, &storage.User{
		ID:          "user-1",
		Email:       "bench@example.com",
		DisplayName: "Bench User",
		CreatedAt:   now,
		UpdatedAt:   now,
	})
	if err != nil {
		b.Fatalf("create user: %v", err)
	}

	// Create a confidential client with client_credentials + authorization_code.
	hasher := crypto.NewBcryptHasher(4)
	secretHash, err := hasher.Hash("bench-secret")
	if err != nil {
		b.Fatalf("hash secret: %v", err)
	}

	err = store.CreateClient(ctx, &storage.Client{
		ID:           "bench-client",
		Name:         "Bench Client",
		SecretHash:   secretHash,
		RedirectURIs: []string{"https://app.example.com/callback"},
		GrantTypes:   []string{"authorization_code", "client_credentials", "refresh_token"},
		Scopes:       []string{"openid", "profile", "email"},
		PKCERequired: true,
		CreatedAt:    now,
		UpdatedAt:    now,
	})
	if err != nil {
		b.Fatalf("create client: %v", err)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatalf("generate key: %v", err)
	}
	signer := crypto.NewEd25519SignerFromKey(priv, "bench-key-1", "https://auth.example.com", time.Hour)

	provider := oidc.NewProvider("https://auth.example.com", signer, store)

	mux := http.NewServeMux()
	provider.RegisterRoutes(mux)

	return &benchHarness{
		store:    store,
		provider: provider,
		mux:      mux,
		signer:   signer,
	}
}

// BenchmarkTokenEndpoint_ClientCredentials benchmarks M2M token issuance.
func BenchmarkTokenEndpoint_ClientCredentials(b *testing.B) {
	h := newBenchHarness(b)

	body := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"bench-client"},
		"client_secret": {"bench-secret"},
		"scope":         {"openid"},
	}.Encode()

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		h.mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			b.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
		}
	}
}

// BenchmarkTokenEndpoint_AuthorizationCode benchmarks full auth code token exchange.
func BenchmarkTokenEndpoint_AuthorizationCode(b *testing.B) {
	h := newBenchHarness(b)

	ctx := context.Background()
	now := time.Now().UTC()

	// Pre-create a pool of auth codes.
	codes := make([]string, b.N)
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challengeBytes := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(challengeBytes[:])

	for i := range codes {
		codes[i] = base64.RawURLEncoding.EncodeToString([]byte(time.Now().String() + string(rune(i))))
		err := h.store.CreateAuthCode(ctx, &storage.AuthCode{
			Code:                codes[i],
			ClientID:            "bench-client",
			UserID:              "user-1",
			RedirectURI:         "https://app.example.com/callback",
			Scopes:              []string{"openid", "profile"},
			CodeChallenge:       challenge,
			CodeChallengeMethod: "S256",
			ExpiresAt:           now.Add(10 * time.Minute),
			CreatedAt:           now,
		})
		if err != nil {
			b.Fatalf("create auth code: %v", err)
		}
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := range codes {
		body := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {codes[i]},
			"redirect_uri":  {"https://app.example.com/callback"},
			"client_id":     {"bench-client"},
			"client_secret": {"bench-secret"},
			"code_verifier": {verifier},
		}.Encode()

		req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		h.mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			b.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
		}
	}
}

// BenchmarkIntrospect benchmarks token introspection.
func BenchmarkIntrospect(b *testing.B) {
	h := newBenchHarness(b)

	// Generate an access token to introspect.
	tokenBody := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"bench-client"},
		"client_secret": {"bench-secret"},
		"scope":         {"openid"},
	}.Encode()

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(tokenBody))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		b.Fatalf("token request failed: %d %s", rec.Code, rec.Body.String())
	}

	var tokenResp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &tokenResp); err != nil {
		b.Fatalf("decode token response: %v", err)
	}
	accessToken := tokenResp["access_token"].(string)

	// Encode client credentials for Basic auth.
	basicAuth := base64.StdEncoding.EncodeToString([]byte("bench-client:bench-secret"))

	body := url.Values{
		"token": {accessToken},
	}.Encode()

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		req := httptest.NewRequest(http.MethodPost, "/introspect", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Basic "+basicAuth)
		rec := httptest.NewRecorder()
		h.mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			b.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
		}
	}
}

// BenchmarkDiscovery benchmarks the OIDC discovery endpoint.
func BenchmarkDiscovery(b *testing.B) {
	h := newBenchHarness(b)

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
		rec := httptest.NewRecorder()
		h.mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			b.Fatalf("expected 200, got %d", rec.Code)
		}
	}
}

// BenchmarkJWKS benchmarks the JWKS endpoint.
func BenchmarkJWKS(b *testing.B) {
	h := newBenchHarness(b)

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
		rec := httptest.NewRecorder()
		h.mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			b.Fatalf("expected 200, got %d", rec.Code)
		}
	}
}
