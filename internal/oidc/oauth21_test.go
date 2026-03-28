package oidc_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/entoten/seki/internal/crypto"
	"github.com/entoten/seki/internal/oidc"
	"github.com/entoten/seki/internal/session"
	"github.com/entoten/seki/internal/storage"

	_ "github.com/entoten/seki/internal/storage/sqlite"
)

// oauth21Harness provides fixtures for OAuth 2.1 conformance tests.
type oauth21Harness struct {
	store    storage.Storage
	sessions *session.Manager
	provider *oidc.Provider
	mux      *http.ServeMux
	signer   crypto.Signer
	cookie   *http.Cookie
}

func newOAuth21Harness(t *testing.T) *oauth21Harness {
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

	// Hash a client secret using bcrypt.
	hasher := crypto.NewBcryptHasher(4)
	secretHash, err := hasher.Hash("test-secret")
	if err != nil {
		t.Fatalf("hash secret: %v", err)
	}

	// Create a confidential client.
	err = store.CreateClient(ctx, &storage.Client{
		ID:           "confidential-client",
		Name:         "Confidential Client",
		SecretHash:   secretHash,
		RedirectURIs: []string{"https://app.example.com/callback"},
		GrantTypes:   []string{"authorization_code", "refresh_token"},
		Scopes:       []string{"openid", "profile", "email"},
		PKCERequired: true,
		CreatedAt:    now,
		UpdatedAt:    now,
	})
	if err != nil {
		t.Fatalf("create confidential client: %v", err)
	}

	// Create a public client (no secret, PKCE required).
	err = store.CreateClient(ctx, &storage.Client{
		ID:           "public-client",
		Name:         "Public Client",
		SecretHash:   "",
		RedirectURIs: []string{"https://public.example.com/callback"},
		GrantTypes:   []string{"authorization_code"},
		Scopes:       []string{"openid", "profile"},
		PKCERequired: true,
		CreatedAt:    now,
		UpdatedAt:    now,
	})
	if err != nil {
		t.Fatalf("create public client: %v", err)
	}

	// Session manager and active session.
	sessCfg := session.Config{CookieName: "seki_session"}
	mgr := session.NewManager(store, sessCfg)

	sess, err := mgr.Create(ctx, "user-1", "", "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	signer := newTestSigner(t)
	provider := oidc.NewProvider("https://auth.example.com", signer, store, oidc.WithSessionManager(mgr))

	mux := http.NewServeMux()
	provider.RegisterRoutes(mux)

	return &oauth21Harness{
		store:    store,
		sessions: mgr,
		provider: provider,
		mux:      mux,
		signer:   signer,
		cookie: &http.Cookie{
			Name:  "seki_session",
			Value: sess.ID,
		},
	}
}

func (h *oauth21Harness) doAuthorize(t *testing.T, params url.Values) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil)
	req.AddCookie(h.cookie)
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)
	return rec.Result()
}

func (h *oauth21Harness) doToken(t *testing.T, params url.Values, basicAuth ...string) *http.Response {
	t.Helper()
	body := params.Encode()
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if len(basicAuth) == 2 {
		req.SetBasicAuth(basicAuth[0], basicAuth[1])
	}
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)
	return rec.Result()
}

func decodeJSON(t *testing.T, resp *http.Response) map[string]interface{} {
	t.Helper()
	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return body
}

// --- OAuth 2.1 Conformance: Implicit Grant REJECTED ---

func TestOAuth21_ImplicitGrant_Rejected(t *testing.T) {
	h := newOAuth21Harness(t)

	// response_type=token is the implicit grant and MUST be rejected.
	params := url.Values{
		"client_id":             {"public-client"},
		"redirect_uri":          {"https://public.example.com/callback"},
		"response_type":         {"token"},
		"scope":                 {"openid profile"},
		"state":                 {"test-state"},
		"code_challenge":        {"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"},
		"code_challenge_method": {"S256"},
	}

	resp := h.doAuthorize(t, params)
	defer resp.Body.Close()

	// Should redirect with error=unsupported_response_type.
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", resp.StatusCode)
	}
	loc, err := resp.Location()
	if err != nil {
		t.Fatalf("no Location header: %v", err)
	}
	if loc.Query().Get("error") != "unsupported_response_type" {
		t.Errorf("error = %q, want unsupported_response_type", loc.Query().Get("error"))
	}
}

func TestOAuth21_ImplicitGrant_ResponseTypeTokenIDToken_Rejected(t *testing.T) {
	h := newOAuth21Harness(t)

	// response_type=token id_token (hybrid implicit) MUST also be rejected.
	params := url.Values{
		"client_id":             {"public-client"},
		"redirect_uri":          {"https://public.example.com/callback"},
		"response_type":         {"token id_token"},
		"scope":                 {"openid profile"},
		"state":                 {"test-state"},
		"code_challenge":        {"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"},
		"code_challenge_method": {"S256"},
	}

	resp := h.doAuthorize(t, params)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", resp.StatusCode)
	}
	loc, _ := resp.Location()
	if loc.Query().Get("error") != "unsupported_response_type" {
		t.Errorf("error = %q, want unsupported_response_type", loc.Query().Get("error"))
	}
}

// --- OAuth 2.1 Conformance: ROPC Grant REJECTED ---

func TestOAuth21_ROPC_Rejected(t *testing.T) {
	h := newOAuth21Harness(t)

	// grant_type=password (ROPC) MUST be rejected.
	params := url.Values{
		"grant_type": {"password"},
		"username":   {"test@example.com"},
		"password":   {"secret123"},
		"client_id":  {"confidential-client"},
	}

	resp := h.doToken(t, params)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
	body := decodeJSON(t, resp)
	if body["error"] != "unsupported_grant_type" {
		t.Errorf("error = %v, want unsupported_grant_type", body["error"])
	}
}

// --- OAuth 2.1 Conformance: PKCE Required for Public Clients ---

func TestOAuth21_PKCE_RequiredForPublicClients(t *testing.T) {
	h := newOAuth21Harness(t)

	// Public client without code_challenge MUST be rejected.
	params := url.Values{
		"client_id":     {"public-client"},
		"redirect_uri":  {"https://public.example.com/callback"},
		"response_type": {"code"},
		"scope":         {"openid profile"},
		"state":         {"test-state"},
	}

	resp := h.doAuthorize(t, params)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", resp.StatusCode)
	}
	loc, _ := resp.Location()
	if loc.Query().Get("error") != "invalid_request" {
		t.Errorf("error = %q, want invalid_request", loc.Query().Get("error"))
	}
}

func TestOAuth21_PKCE_OnlyS256Supported(t *testing.T) {
	h := newOAuth21Harness(t)

	// code_challenge_method=plain MUST be rejected per OAuth 2.1.
	params := url.Values{
		"client_id":             {"public-client"},
		"redirect_uri":          {"https://public.example.com/callback"},
		"response_type":         {"code"},
		"scope":                 {"openid profile"},
		"state":                 {"test-state"},
		"code_challenge":        {"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"},
		"code_challenge_method": {"plain"},
	}

	resp := h.doAuthorize(t, params)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", resp.StatusCode)
	}
	loc, _ := resp.Location()
	if loc.Query().Get("error") != "invalid_request" {
		t.Errorf("error = %q, want invalid_request", loc.Query().Get("error"))
	}
}

// --- OAuth 2.1 Conformance: Refresh Token Rotation Enforced ---

func TestOAuth21_RefreshTokenRotation_Enforced(t *testing.T) {
	h := newOAuth21Harness(t)
	ctx := context.Background()

	// Create a refresh token.
	rawToken := "oauth21-refresh-token"
	tokenHash := sha256Hex(rawToken)
	now := time.Now().UTC()

	rt := &storage.RefreshToken{
		ID:        "rt-oauth21",
		TokenHash: tokenHash,
		ClientID:  "confidential-client",
		UserID:    "user-1",
		Scopes:    []string{"openid", "profile"},
		Family:    "family-oauth21",
		ExpiresAt: now.Add(30 * 24 * time.Hour),
		CreatedAt: now,
	}
	if err := h.store.CreateRefreshToken(ctx, rt); err != nil {
		t.Fatalf("create refresh token: %v", err)
	}

	params := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rawToken},
		"client_id":     {"confidential-client"},
		"client_secret": {"test-secret"},
	}

	// First use succeeds and returns a NEW refresh token.
	resp := h.doToken(t, params)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body := decodeJSON(t, resp)
		t.Fatalf("expected 200, got %d: %v", resp.StatusCode, body)
	}

	body := decodeJSON(t, resp)
	newRefreshToken := body["refresh_token"]
	if newRefreshToken == nil || newRefreshToken == "" {
		t.Fatal("expected new refresh_token in response")
	}
	if newRefreshToken == rawToken {
		t.Error("new refresh token must be different from the old one (rotation)")
	}

	// Old token is now consumed. Reusing it MUST fail.
	resp2 := h.doToken(t, params)
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 on reuse of rotated token, got %d", resp2.StatusCode)
	}
	body2 := decodeJSON(t, resp2)
	if body2["error"] != "invalid_grant" {
		t.Errorf("error = %v, want invalid_grant", body2["error"])
	}
}

func TestOAuth21_RefreshTokenReuse_RevokesFamily(t *testing.T) {
	h := newOAuth21Harness(t)
	ctx := context.Background()

	now := time.Now().UTC()
	family := "family-reuse-test"

	// Create first token in the family.
	rawToken1 := "reuse-token-1"
	hash1 := sha256Hex(rawToken1)
	rt1 := &storage.RefreshToken{
		ID:        "rt-reuse-1",
		TokenHash: hash1,
		ClientID:  "confidential-client",
		UserID:    "user-1",
		Scopes:    []string{"openid"},
		Family:    family,
		ExpiresAt: now.Add(30 * 24 * time.Hour),
		CreatedAt: now,
	}
	if err := h.store.CreateRefreshToken(ctx, rt1); err != nil {
		t.Fatalf("create rt1: %v", err)
	}

	params := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rawToken1},
		"client_id":     {"confidential-client"},
		"client_secret": {"test-secret"},
	}

	// Rotate token1 normally.
	resp := h.doToken(t, params)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body := decodeJSON(t, resp)
		t.Fatalf("expected 200, got %d: %v", resp.StatusCode, body)
	}
	firstBody := decodeJSON(t, resp)
	newRawToken := firstBody["refresh_token"].(string)

	// Reuse old token1 (simulates theft).
	resp2 := h.doToken(t, params)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 on token reuse, got %d", resp2.StatusCode)
	}

	// The new token (from rotation) should also be revoked (whole family).
	newHash := sha256Hex(newRawToken)
	_, err := h.store.GetRefreshTokenByHash(ctx, newHash)
	if err != storage.ErrNotFound {
		t.Errorf("new token in family should be revoked after reuse detection, got err: %v", err)
	}
}

// --- OAuth 2.1 Conformance: Redirect URI Exact Matching ---

func TestOAuth21_RedirectURI_ExactMatchRequired(t *testing.T) {
	h := newOAuth21Harness(t)

	tests := []struct {
		name        string
		redirectURI string
	}{
		{"trailing slash", "https://public.example.com/callback/"},
		{"query param added", "https://public.example.com/callback?extra=1"},
		{"different host", "https://evil.example.com/callback"},
		{"different scheme", "http://public.example.com/callback"},
		{"subpath", "https://public.example.com/callback/extra"},
		{"wildcard attempt", "https://*.example.com/callback"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := url.Values{
				"client_id":             {"public-client"},
				"redirect_uri":          {tt.redirectURI},
				"response_type":         {"code"},
				"scope":                 {"openid profile"},
				"state":                 {"test-state"},
				"code_challenge":        {"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"},
				"code_challenge_method": {"S256"},
			}

			resp := h.doAuthorize(t, params)
			defer resp.Body.Close()

			// Must NOT redirect to the invalid URI. Should render an error page.
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("expected 400 for redirect_uri %q, got %d", tt.redirectURI, resp.StatusCode)
			}
			// Must not have a Location header pointing to the bad URI.
			if loc := resp.Header.Get("Location"); loc != "" && strings.Contains(loc, tt.redirectURI) {
				t.Errorf("should not redirect to unvalidated URI %q", tt.redirectURI)
			}
		})
	}
}

func TestOAuth21_RedirectURI_ExactMatchSucceeds(t *testing.T) {
	h := newOAuth21Harness(t)

	// The exact registered URI should work.
	params := url.Values{
		"client_id":             {"public-client"},
		"redirect_uri":          {"https://public.example.com/callback"},
		"response_type":         {"code"},
		"scope":                 {"openid profile"},
		"state":                 {"test-state"},
		"code_challenge":        {"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"},
		"code_challenge_method": {"S256"},
	}

	resp := h.doAuthorize(t, params)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", resp.StatusCode)
	}
	loc, err := resp.Location()
	if err != nil {
		t.Fatalf("no Location header: %v", err)
	}
	if loc.Query().Get("code") == "" {
		t.Error("expected authorization code in redirect")
	}
}

// --- OAuth 2.1 Conformance: Discovery Excludes Implicit and ROPC ---

func TestOAuth21_Discovery_GrantTypesExcludeImplicitAndROPC(t *testing.T) {
	signer := newTestSigner(t)
	provider := oidc.NewProvider("https://auth.example.com", signer, nil)

	mux := http.NewServeMux()
	provider.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	grantTypes, ok := body["grant_types_supported"].([]interface{})
	if !ok {
		t.Fatal("grant_types_supported missing or not an array")
	}

	for _, gt := range grantTypes {
		gtStr, _ := gt.(string)
		if gtStr == "implicit" {
			t.Error("grant_types_supported must NOT include 'implicit'")
		}
		if gtStr == "password" {
			t.Error("grant_types_supported must NOT include 'password' (ROPC)")
		}
	}

	// Verify expected grant types are present.
	expected := map[string]bool{
		"authorization_code": false,
		"client_credentials": false,
		"refresh_token":      false,
	}
	for _, gt := range grantTypes {
		gtStr, _ := gt.(string)
		if _, ok := expected[gtStr]; ok {
			expected[gtStr] = true
		}
	}
	for gt, found := range expected {
		if !found {
			t.Errorf("grant_types_supported should include %q", gt)
		}
	}
}

func TestOAuth21_Discovery_ResponseTypesOnlyCode(t *testing.T) {
	signer := newTestSigner(t)
	provider := oidc.NewProvider("https://auth.example.com", signer, nil)

	mux := http.NewServeMux()
	provider.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var body map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)

	responseTypes, ok := body["response_types_supported"].([]interface{})
	if !ok {
		t.Fatal("response_types_supported missing or not an array")
	}

	for _, rt := range responseTypes {
		rtStr, _ := rt.(string)
		if rtStr == "token" {
			t.Error("response_types_supported must NOT include 'token' (implicit)")
		}
	}

	if len(responseTypes) != 1 || responseTypes[0] != "code" {
		t.Errorf("response_types_supported = %v, want [code]", responseTypes)
	}
}

// sha256Hex computes the SHA-256 hex hash of a string.
func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

