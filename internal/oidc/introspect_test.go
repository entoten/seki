package oidc_test

import (
	"context"
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

// introspectHarness sets up a provider with test data for introspection tests.
type introspectHarness struct {
	store    storage.Storage
	provider *oidc.Provider
	mux      *http.ServeMux
	signer   crypto.Signer
}

func newIntrospectHarness(t *testing.T) *introspectHarness {
	t.Helper()

	store, err := storage.New(storage.TestDatabaseConfig())
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	if err := store.Migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	ctx := context.Background()
	now := time.Now().UTC()

	// Create a test user.
	err = store.CreateUser(ctx, &storage.User{
		ID:          "user-1",
		Email:       "test@example.com",
		DisplayName: "Test User",
		CreatedAt:   now,
		UpdatedAt:   now,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	// Create a confidential client.
	hasher := crypto.NewBcryptHasher(4)
	secretHash, err := hasher.Hash("test-secret")
	if err != nil {
		t.Fatalf("hash secret: %v", err)
	}
	err = store.CreateClient(ctx, &storage.Client{
		ID:           "test-client",
		Name:         "Test Client",
		SecretHash:   secretHash,
		RedirectURIs: []string{"https://app.example.com/callback"},
		GrantTypes:   []string{"authorization_code", "refresh_token"},
		Scopes:       []string{"openid", "profile", "email"},
		PKCERequired: true,
		CreatedAt:    now,
		UpdatedAt:    now,
	})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	signer := newTestSigner(t)
	provider := oidc.NewProvider("https://auth.example.com", signer, store)

	mux := http.NewServeMux()
	provider.RegisterRoutes(mux)

	return &introspectHarness{
		store:    store,
		provider: provider,
		mux:      mux,
		signer:   signer,
	}
}

func (h *introspectHarness) doIntrospect(t *testing.T, params url.Values, basicAuth ...string) *http.Response {
	t.Helper()
	body := params.Encode()
	req := httptest.NewRequest(http.MethodPost, "/introspect", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if len(basicAuth) == 2 {
		req.SetBasicAuth(basicAuth[0], basicAuth[1])
	}
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)
	return rec.Result()
}

func decodeIntrospectResponse(t *testing.T, resp *http.Response) map[string]interface{} {
	t.Helper()
	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return body
}

func TestIntrospect_ValidJWT_ReturnsActive(t *testing.T) {
	h := newIntrospectHarness(t)

	// Generate a valid access token.
	now := time.Now().UTC()
	claims := map[string]interface{}{
		"sub":   "user-1",
		"aud":   "test-client",
		"scope": "openid profile email",
		"iat":   now.Unix(),
		"exp":   now.Add(15 * time.Minute).Unix(),
		"iss":   "https://auth.example.com",
		"typ":   "access_token",
	}
	token, err := h.signer.Sign(claims)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	params := url.Values{
		"token": {token},
	}
	resp := h.doIntrospect(t, params, "test-client", "test-secret")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	body := decodeIntrospectResponse(t, resp)
	if body["active"] != true {
		t.Fatalf("expected active=true, got %v", body["active"])
	}
	if body["sub"] != "user-1" {
		t.Errorf("sub = %v, want user-1", body["sub"])
	}
	if body["client_id"] != "test-client" {
		t.Errorf("client_id = %v, want test-client", body["client_id"])
	}
	if body["scope"] != "openid profile email" {
		t.Errorf("scope = %v, want 'openid profile email'", body["scope"])
	}
	if body["token_type"] != "Bearer" {
		t.Errorf("token_type = %v, want Bearer", body["token_type"])
	}
}

func TestIntrospect_ExpiredJWT_ReturnsInactive(t *testing.T) {
	h := newIntrospectHarness(t)

	// Generate an expired access token by signing with past times.
	past := time.Now().UTC().Add(-1 * time.Hour)
	claims := map[string]interface{}{
		"sub":   "user-1",
		"aud":   "test-client",
		"scope": "openid",
		"iat":   past.Unix(),
		"exp":   past.Add(15 * time.Minute).Unix(), // expired 45 min ago
		"iss":   "https://auth.example.com",
		"typ":   "access_token",
	}
	token, err := h.signer.Sign(claims)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	params := url.Values{
		"token": {token},
	}
	resp := h.doIntrospect(t, params, "test-client", "test-secret")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	body := decodeIntrospectResponse(t, resp)
	if body["active"] != false {
		t.Fatalf("expected active=false for expired token, got %v", body["active"])
	}
}

func TestIntrospect_InvalidJWT_ReturnsInactive(t *testing.T) {
	h := newIntrospectHarness(t)

	params := url.Values{
		"token": {"this.is.not.a.valid.jwt"},
	}
	resp := h.doIntrospect(t, params, "test-client", "test-secret")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	body := decodeIntrospectResponse(t, resp)
	if body["active"] != false {
		t.Fatalf("expected active=false for invalid token, got %v", body["active"])
	}
}

func TestIntrospect_ValidRefreshToken_ReturnsActive(t *testing.T) {
	h := newIntrospectHarness(t)

	rawToken := "introspect-refresh-token"
	hash := hashForTest(rawToken)
	now := time.Now().UTC()

	rt := &storage.RefreshToken{
		ID:        "rt-intro-1",
		TokenHash: hash,
		ClientID:  "test-client",
		UserID:    "user-1",
		Scopes:    []string{"openid", "profile"},
		Family:    "family-intro-1",
		ExpiresAt: now.Add(30 * 24 * time.Hour),
		CreatedAt: now,
	}
	if err := h.store.CreateRefreshToken(context.Background(), rt); err != nil {
		t.Fatalf("create refresh token: %v", err)
	}

	params := url.Values{
		"token":           {rawToken},
		"token_type_hint": {"refresh_token"},
	}
	resp := h.doIntrospect(t, params, "test-client", "test-secret")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	body := decodeIntrospectResponse(t, resp)
	if body["active"] != true {
		t.Fatalf("expected active=true, got %v", body["active"])
	}
	if body["sub"] != "user-1" {
		t.Errorf("sub = %v, want user-1", body["sub"])
	}
	if body["client_id"] != "test-client" {
		t.Errorf("client_id = %v, want test-client", body["client_id"])
	}
}

func TestIntrospect_RevokedRefreshToken_ReturnsInactive(t *testing.T) {
	h := newIntrospectHarness(t)

	rawToken := "revoked-refresh-token"
	hash := hashForTest(rawToken)
	now := time.Now().UTC()

	// Create a consumed (revoked) refresh token with sentinel expiry.
	rt := &storage.RefreshToken{
		ID:        "rt-revoked-1",
		TokenHash: hash,
		ClientID:  "test-client",
		UserID:    "user-1",
		Scopes:    []string{"openid"},
		Family:    "family-revoked-1",
		ExpiresAt: time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC), // consumed sentinel
		CreatedAt: now,
	}
	if err := h.store.CreateRefreshToken(context.Background(), rt); err != nil {
		t.Fatalf("create refresh token: %v", err)
	}

	params := url.Values{
		"token":           {rawToken},
		"token_type_hint": {"refresh_token"},
	}
	resp := h.doIntrospect(t, params, "test-client", "test-secret")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	body := decodeIntrospectResponse(t, resp)
	if body["active"] != false {
		t.Fatalf("expected active=false for revoked refresh token, got %v", body["active"])
	}
}

func TestIntrospect_MissingToken_ReturnsError(t *testing.T) {
	h := newIntrospectHarness(t)

	params := url.Values{}
	resp := h.doIntrospect(t, params, "test-client", "test-secret")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}

	body := decodeIntrospectResponse(t, resp)
	if body["error"] != "invalid_request" {
		t.Errorf("error = %v, want invalid_request", body["error"])
	}
}

func TestIntrospect_UnauthenticatedCaller_Returns401(t *testing.T) {
	h := newIntrospectHarness(t)

	params := url.Values{
		"token": {"some-token"},
	}
	// No basic auth credentials.
	resp := h.doIntrospect(t, params)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestIntrospect_ValidPAT_ReturnsActive(t *testing.T) {
	h := newIntrospectHarness(t)

	rawToken := "introspect-pat-token"
	hash := hashForTest(rawToken)
	now := time.Now().UTC()

	pat := &storage.PersonalAccessToken{
		ID:        "pat-intro-1",
		UserID:    "user-1",
		Name:      "Test PAT",
		TokenHash: hash,
		Scopes:    []string{"read", "write"},
		ExpiresAt: now.Add(90 * 24 * time.Hour),
		CreatedAt: now,
	}
	if err := h.store.CreatePAT(context.Background(), pat); err != nil {
		t.Fatalf("create PAT: %v", err)
	}

	params := url.Values{
		"token": {rawToken},
	}
	resp := h.doIntrospect(t, params, "test-client", "test-secret")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	body := decodeIntrospectResponse(t, resp)
	if body["active"] != true {
		t.Fatalf("expected active=true for PAT, got %v", body["active"])
	}
	if body["sub"] != "user-1" {
		t.Errorf("sub = %v, want user-1", body["sub"])
	}
}
