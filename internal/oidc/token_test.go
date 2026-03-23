package oidc_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Monet/seki/internal/crypto"
	"github.com/Monet/seki/internal/oidc"
	"github.com/Monet/seki/internal/storage"

	_ "github.com/Monet/seki/internal/storage/sqlite"
)

// tokenHarness extends the test harness with helpers specific to token tests.
type tokenHarness struct {
	store    storage.Storage
	provider *oidc.Provider
	mux      *http.ServeMux
	signer   crypto.Signer
}

func newTokenHarness(t *testing.T) *tokenHarness {
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
	hasher := crypto.NewBcryptHasher(4) // low cost for tests
	secretHash, err := hasher.Hash("test-secret")
	if err != nil {
		t.Fatalf("hash secret: %v", err)
	}

	// Create a confidential client with authorization_code grant.
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

	// Create a public client (no secret).
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

	// Create a client with client_credentials grant.
	ccSecretHash, err := hasher.Hash("cc-secret")
	if err != nil {
		t.Fatalf("hash cc secret: %v", err)
	}
	err = store.CreateClient(ctx, &storage.Client{
		ID:           "cc-client",
		Name:         "CC Client",
		SecretHash:   ccSecretHash,
		RedirectURIs: nil,
		GrantTypes:   []string{"client_credentials"},
		Scopes:       []string{"openid"},
		PKCERequired: false,
		CreatedAt:    now,
		UpdatedAt:    now,
	})
	if err != nil {
		t.Fatalf("create cc client: %v", err)
	}

	signer := newTestSigner(t)
	provider := oidc.NewProvider("https://auth.example.com", signer, store)

	mux := http.NewServeMux()
	provider.RegisterRoutes(mux)

	return &tokenHarness{
		store:    store,
		provider: provider,
		mux:      mux,
		signer:   signer,
	}
}

// createAuthCode inserts an authorization code directly into the store.
func (h *tokenHarness) createAuthCode(t *testing.T, code, clientID, userID, redirectURI, codeChallenge, nonce string, scopes []string, expiresAt time.Time) {
	t.Helper()
	now := time.Now().UTC()
	ac := &storage.AuthCode{
		Code:                code,
		ClientID:            clientID,
		UserID:              userID,
		RedirectURI:         redirectURI,
		Scopes:              scopes,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: "S256",
		Nonce:               nonce,
		ExpiresAt:           expiresAt,
		CreatedAt:           now,
	}
	if err := h.store.CreateAuthCode(context.Background(), ac); err != nil {
		t.Fatalf("create auth code: %v", err)
	}
}

func (h *tokenHarness) doTokenRequest(t *testing.T, params url.Values, basicAuth ...string) *http.Response {
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

func decodeTokenResponse(t *testing.T, resp *http.Response) map[string]interface{} {
	t.Helper()
	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return body
}

// computeS256Challenge computes a PKCE S256 challenge from a verifier.
func computeS256Challenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// --- Tests ---

func TestToken_AuthorizationCode_ValidExchange(t *testing.T) {
	h := newTokenHarness(t)

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := computeS256Challenge(verifier)

	h.createAuthCode(t, "test-code-1", "test-client", "user-1",
		"https://app.example.com/callback", challenge, "test-nonce",
		[]string{"openid", "profile"}, time.Now().Add(10*time.Minute))

	params := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"test-code-1"},
		"redirect_uri":  {"https://app.example.com/callback"},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
		"code_verifier": {verifier},
	}

	resp := h.doTokenRequest(t, params)
	if resp.StatusCode != http.StatusOK {
		body := decodeTokenResponse(t, resp)
		t.Fatalf("expected 200, got %d: %v", resp.StatusCode, body)
	}

	body := decodeTokenResponse(t, resp)

	// Verify all expected fields are present.
	if body["access_token"] == nil || body["access_token"] == "" {
		t.Error("missing access_token")
	}
	if body["id_token"] == nil || body["id_token"] == "" {
		t.Error("missing id_token")
	}
	if body["refresh_token"] == nil || body["refresh_token"] == "" {
		t.Error("missing refresh_token")
	}
	if body["token_type"] != "Bearer" {
		t.Errorf("token_type = %v, want Bearer", body["token_type"])
	}
	if body["expires_in"] != float64(900) {
		t.Errorf("expires_in = %v, want 900", body["expires_in"])
	}

	// Verify access token is a valid JWT.
	claims, err := h.signer.Verify(body["access_token"].(string))
	if err != nil {
		t.Fatalf("verify access token: %v", err)
	}
	if claims["sub"] != "user-1" {
		t.Errorf("access token sub = %v, want user-1", claims["sub"])
	}

	// Verify ID token is a valid JWT with OIDC claims.
	idClaims, err := h.signer.Verify(body["id_token"].(string))
	if err != nil {
		t.Fatalf("verify id token: %v", err)
	}
	if idClaims["sub"] != "user-1" {
		t.Errorf("id token sub = %v, want user-1", idClaims["sub"])
	}
	if idClaims["aud"] != "test-client" {
		t.Errorf("id token aud = %v, want test-client", idClaims["aud"])
	}
	if idClaims["nonce"] != "test-nonce" {
		t.Errorf("id token nonce = %v, want test-nonce", idClaims["nonce"])
	}
	if idClaims["email"] != "test@example.com" {
		t.Errorf("id token email = %v, want test@example.com", idClaims["email"])
	}
	if idClaims["name"] != "Test User" {
		t.Errorf("id token name = %v, want Test User", idClaims["name"])
	}
}

func TestToken_AuthorizationCode_PKCEVerification(t *testing.T) {
	h := newTokenHarness(t)

	verifier := "correct-verifier-value-for-pkce-test"
	challenge := computeS256Challenge(verifier)

	h.createAuthCode(t, "pkce-code", "test-client", "user-1",
		"https://app.example.com/callback", challenge, "",
		[]string{"openid"}, time.Now().Add(10*time.Minute))

	// Wrong verifier should fail.
	params := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"pkce-code"},
		"redirect_uri":  {"https://app.example.com/callback"},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
		"code_verifier": {"wrong-verifier"},
	}

	resp := h.doTokenRequest(t, params)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
	body := decodeTokenResponse(t, resp)
	if body["error"] != "invalid_grant" {
		t.Errorf("error = %v, want invalid_grant", body["error"])
	}
}

func TestToken_AuthorizationCode_SingleUse(t *testing.T) {
	h := newTokenHarness(t)

	verifier := "single-use-verifier"
	challenge := computeS256Challenge(verifier)

	h.createAuthCode(t, "single-use-code", "test-client", "user-1",
		"https://app.example.com/callback", challenge, "",
		[]string{"openid"}, time.Now().Add(10*time.Minute))

	params := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"single-use-code"},
		"redirect_uri":  {"https://app.example.com/callback"},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
		"code_verifier": {verifier},
	}

	// First use should succeed.
	resp := h.doTokenRequest(t, params)
	if resp.StatusCode != http.StatusOK {
		body := decodeTokenResponse(t, resp)
		t.Fatalf("expected 200, got %d: %v", resp.StatusCode, body)
	}
	// Consume the body.
	decodeTokenResponse(t, resp)

	// Second use should fail.
	resp2 := h.doTokenRequest(t, params)
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 on second use, got %d", resp2.StatusCode)
	}
	body2 := decodeTokenResponse(t, resp2)
	if body2["error"] != "invalid_grant" {
		t.Errorf("error = %v, want invalid_grant", body2["error"])
	}
}

func TestToken_AuthorizationCode_ExpiredCode(t *testing.T) {
	h := newTokenHarness(t)

	verifier := "expired-code-verifier"
	challenge := computeS256Challenge(verifier)

	// Create an already-expired code.
	h.createAuthCode(t, "expired-code", "test-client", "user-1",
		"https://app.example.com/callback", challenge, "",
		[]string{"openid"}, time.Now().Add(-1*time.Minute))

	params := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"expired-code"},
		"redirect_uri":  {"https://app.example.com/callback"},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
		"code_verifier": {verifier},
	}

	resp := h.doTokenRequest(t, params)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
	body := decodeTokenResponse(t, resp)
	if body["error"] != "invalid_grant" {
		t.Errorf("error = %v, want invalid_grant", body["error"])
	}
}

func TestToken_ClientCredentials_ReturnsAccessTokenOnly(t *testing.T) {
	h := newTokenHarness(t)

	params := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"cc-client"},
		"client_secret": {"cc-secret"},
		"scope":         {"openid"},
	}

	resp := h.doTokenRequest(t, params)
	if resp.StatusCode != http.StatusOK {
		body := decodeTokenResponse(t, resp)
		t.Fatalf("expected 200, got %d: %v", resp.StatusCode, body)
	}

	body := decodeTokenResponse(t, resp)

	if body["access_token"] == nil || body["access_token"] == "" {
		t.Error("missing access_token")
	}
	if body["token_type"] != "Bearer" {
		t.Errorf("token_type = %v, want Bearer", body["token_type"])
	}
	// Should NOT have id_token or refresh_token.
	if body["id_token"] != nil {
		t.Errorf("client_credentials should not return id_token, got %v", body["id_token"])
	}
	if body["refresh_token"] != nil {
		t.Errorf("client_credentials should not return refresh_token, got %v", body["refresh_token"])
	}
}

func TestToken_ClientCredentials_RequiresSecret(t *testing.T) {
	h := newTokenHarness(t)

	params := url.Values{
		"grant_type": {"client_credentials"},
		"client_id":  {"cc-client"},
	}

	resp := h.doTokenRequest(t, params)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
	body := decodeTokenResponse(t, resp)
	if body["error"] != "invalid_client" {
		t.Errorf("error = %v, want invalid_client", body["error"])
	}
}

func TestToken_ClientCredentials_BasicAuth(t *testing.T) {
	h := newTokenHarness(t)

	params := url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {"openid"},
	}

	resp := h.doTokenRequest(t, params, "cc-client", "cc-secret")
	if resp.StatusCode != http.StatusOK {
		body := decodeTokenResponse(t, resp)
		t.Fatalf("expected 200, got %d: %v", resp.StatusCode, body)
	}

	body := decodeTokenResponse(t, resp)
	if body["access_token"] == nil || body["access_token"] == "" {
		t.Error("missing access_token")
	}
}

func TestToken_RefreshToken_ReturnsNewTokens(t *testing.T) {
	h := newTokenHarness(t)

	// Create initial refresh token in the store.
	rawToken := "test-refresh-token-value"
	tokenHash := hashForTest(rawToken)
	now := time.Now().UTC()

	rt := &storage.RefreshToken{
		ID:        "rt-1",
		TokenHash: tokenHash,
		ClientID:  "test-client",
		UserID:    "user-1",
		Scopes:    []string{"openid", "profile"},
		Family:    "family-1",
		ExpiresAt: now.Add(30 * 24 * time.Hour),
		CreatedAt: now,
	}
	if err := h.store.CreateRefreshToken(context.Background(), rt); err != nil {
		t.Fatalf("create refresh token: %v", err)
	}

	params := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rawToken},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
	}

	resp := h.doTokenRequest(t, params)
	if resp.StatusCode != http.StatusOK {
		body := decodeTokenResponse(t, resp)
		t.Fatalf("expected 200, got %d: %v", resp.StatusCode, body)
	}

	body := decodeTokenResponse(t, resp)

	if body["access_token"] == nil || body["access_token"] == "" {
		t.Error("missing access_token")
	}
	if body["id_token"] == nil || body["id_token"] == "" {
		t.Error("missing id_token")
	}
	if body["refresh_token"] == nil || body["refresh_token"] == "" {
		t.Error("missing refresh_token")
	}
	// New refresh token should be different from the old one.
	if body["refresh_token"] == rawToken {
		t.Error("new refresh token should be different from old one")
	}
}

func TestToken_RefreshToken_OldTokenInvalidated(t *testing.T) {
	h := newTokenHarness(t)

	rawToken := "refresh-to-rotate"
	tokenHash := hashForTest(rawToken)
	now := time.Now().UTC()

	rt := &storage.RefreshToken{
		ID:        "rt-rotate",
		TokenHash: tokenHash,
		ClientID:  "test-client",
		UserID:    "user-1",
		Scopes:    []string{"openid"},
		Family:    "family-rotate",
		ExpiresAt: now.Add(30 * 24 * time.Hour),
		CreatedAt: now,
	}
	if err := h.store.CreateRefreshToken(context.Background(), rt); err != nil {
		t.Fatalf("create refresh token: %v", err)
	}

	params := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rawToken},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
	}

	resp := h.doTokenRequest(t, params)
	if resp.StatusCode != http.StatusOK {
		body := decodeTokenResponse(t, resp)
		t.Fatalf("expected 200, got %d: %v", resp.StatusCode, body)
	}
	decodeTokenResponse(t, resp)

	// Old token should still exist in the store but be marked as consumed
	// (expiry set to the sentinel epoch value for theft detection).
	consumed, err := h.store.GetRefreshTokenByHash(context.Background(), tokenHash)
	if err != nil {
		t.Fatalf("old refresh token should still exist (consumed), got err: %v", err)
	}
	consumedSentinel := time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	if !consumed.ExpiresAt.Equal(consumedSentinel) {
		t.Errorf("consumed token expires_at = %v, want sentinel %v", consumed.ExpiresAt, consumedSentinel)
	}

	// Using the old token again should fail (theft detection).
	resp2 := h.doTokenRequest(t, params)
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 on reuse, got %d", resp2.StatusCode)
	}
	body2 := decodeTokenResponse(t, resp2)
	if body2["error"] != "invalid_grant" {
		t.Errorf("error = %v, want invalid_grant", body2["error"])
	}
}

func TestToken_RefreshToken_TheftDetection(t *testing.T) {
	h := newTokenHarness(t)
	ctx := context.Background()

	// Create two refresh tokens in the same family.
	now := time.Now().UTC()
	family := "theft-family"

	rawToken1 := "theft-token-1"
	hash1 := hashForTest(rawToken1)
	rt1 := &storage.RefreshToken{
		ID:        "rt-theft-1",
		TokenHash: hash1,
		ClientID:  "test-client",
		UserID:    "user-1",
		Scopes:    []string{"openid"},
		Family:    family,
		ExpiresAt: now.Add(30 * 24 * time.Hour),
		CreatedAt: now,
	}
	if err := h.store.CreateRefreshToken(ctx, rt1); err != nil {
		t.Fatalf("create rt1: %v", err)
	}

	rawToken2 := "theft-token-2"
	hash2 := hashForTest(rawToken2)
	rt2 := &storage.RefreshToken{
		ID:        "rt-theft-2",
		TokenHash: hash2,
		ClientID:  "test-client",
		UserID:    "user-1",
		Scopes:    []string{"openid"},
		Family:    family,
		ExpiresAt: now.Add(30 * 24 * time.Hour),
		CreatedAt: now,
	}
	if err := h.store.CreateRefreshToken(ctx, rt2); err != nil {
		t.Fatalf("create rt2: %v", err)
	}

	// Use token1 normally (this rotates it).
	params := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rawToken1},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
	}
	resp := h.doTokenRequest(t, params)
	if resp.StatusCode != http.StatusOK {
		body := decodeTokenResponse(t, resp)
		t.Fatalf("expected 200, got %d: %v", resp.StatusCode, body)
	}
	decodeTokenResponse(t, resp)

	// Now try to reuse token1 (already deleted) - this simulates theft.
	resp2 := h.doTokenRequest(t, params)
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 on theft detection, got %d", resp2.StatusCode)
	}
	body2 := decodeTokenResponse(t, resp2)
	if body2["error"] != "invalid_grant" {
		t.Errorf("error = %v, want invalid_grant", body2["error"])
	}

	// Token2 (same family) should also be revoked.
	_, err := h.store.GetRefreshTokenByHash(ctx, hash2)
	if err != storage.ErrNotFound {
		t.Errorf("token2 in same family should be revoked, got err: %v", err)
	}
}

func TestToken_InvalidGrantType(t *testing.T) {
	h := newTokenHarness(t)

	params := url.Values{
		"grant_type": {"implicit"},
	}

	resp := h.doTokenRequest(t, params)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
	body := decodeTokenResponse(t, resp)
	if body["error"] != "unsupported_grant_type" {
		t.Errorf("error = %v, want unsupported_grant_type", body["error"])
	}
}

func TestToken_AuthorizationCode_PublicClient(t *testing.T) {
	h := newTokenHarness(t)

	verifier := "public-client-verifier"
	challenge := computeS256Challenge(verifier)

	h.createAuthCode(t, "public-code", "public-client", "user-1",
		"https://public.example.com/callback", challenge, "",
		[]string{"openid"}, time.Now().Add(10*time.Minute))

	params := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"public-code"},
		"redirect_uri":  {"https://public.example.com/callback"},
		"client_id":     {"public-client"},
		"code_verifier": {verifier},
	}

	resp := h.doTokenRequest(t, params)
	if resp.StatusCode != http.StatusOK {
		body := decodeTokenResponse(t, resp)
		t.Fatalf("expected 200, got %d: %v", resp.StatusCode, body)
	}

	body := decodeTokenResponse(t, resp)
	if body["access_token"] == nil || body["access_token"] == "" {
		t.Error("missing access_token")
	}
}

// hashForTest computes the SHA-256 hex hash of a token (mirrors hashToken in token_helpers.go).
func hashForTest(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
