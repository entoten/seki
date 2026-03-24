package oidc_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/entoten/seki/internal/config"
	"github.com/entoten/seki/internal/oidc"
	"github.com/entoten/seki/internal/ratelimit"
	"github.com/entoten/seki/internal/session"
	"github.com/entoten/seki/internal/storage"
	_ "github.com/entoten/seki/internal/storage/sqlite"
)

func TestPasswordLogin_PasswordNotEnabled(t *testing.T) {
	h := newLoginTestHarness(t, config.AuthenticationConfig{
		Password: config.PasswordConfig{Enabled: false},
	})

	form := url.Values{
		"email":    {"test@example.com"},
		"password": {"somepassword"},
	}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)

	body, _ := io.ReadAll(rec.Result().Body)
	if !strings.Contains(string(body), "Password authentication is not enabled") {
		t.Error("expected password not enabled error")
	}
}

func TestPasswordLogin_MissingFields(t *testing.T) {
	h := newLoginTestHarness(t, config.AuthenticationConfig{
		Password: config.PasswordConfig{Enabled: true},
	})

	form := url.Values{
		"email": {"test@example.com"},
	}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)

	body, _ := io.ReadAll(rec.Result().Body)
	if !strings.Contains(string(body), "Email and password are required") {
		t.Error("expected missing fields error")
	}
}

func TestPasswordLogin_UnknownEmail(t *testing.T) {
	h := newLoginTestHarness(t, config.AuthenticationConfig{
		Password: config.PasswordConfig{Enabled: true},
	})

	form := url.Values{
		"email":    {"unknown@example.com"},
		"password": {"somepassword"},
	}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)

	body, _ := io.ReadAll(rec.Result().Body)
	if !strings.Contains(string(body), "Invalid email or password") {
		t.Error("expected invalid credentials error")
	}
}

func TestPasswordLogin_NoCredentials(t *testing.T) {
	h := newLoginTestHarness(t, config.AuthenticationConfig{
		Password: config.PasswordConfig{Enabled: true},
	})

	// User exists but has no password credential.
	form := url.Values{
		"email":    {"test@example.com"},
		"password": {"somepassword"},
	}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)

	body, _ := io.ReadAll(rec.Result().Body)
	if !strings.Contains(string(body), "Invalid email or password") {
		t.Error("expected invalid credentials error for user with no credentials")
	}
}

func TestLogout_WithRedirectURI(t *testing.T) {
	h := newLoginTestHarness(t, config.AuthenticationConfig{})

	// POST /logout with redirect_uri.
	form := url.Values{
		"redirect_uri": {"/custom-page"},
	}
	req := httptest.NewRequest(http.MethodPost, "/logout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rec.Code)
	}
	loc, _ := rec.Result().Location()
	if loc.Path != "/custom-page" {
		t.Errorf("redirect to %q, want /custom-page", loc.Path)
	}
}

func TestLogout_UnsafeRedirect(t *testing.T) {
	h := newLoginTestHarness(t, config.AuthenticationConfig{})

	form := url.Values{
		"redirect_uri": {"https://evil.example.com/phish"},
	}
	req := httptest.NewRequest(http.MethodPost, "/logout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rec.Code)
	}
	loc, _ := rec.Result().Location()
	// Should redirect to issuer, not to the evil URL.
	if strings.Contains(loc.String(), "evil") {
		t.Errorf("should not redirect to evil URL: %s", loc.String())
	}
}

func TestPasswordLogin_WithRateLimiter(t *testing.T) {
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

	err = store.CreateUser(ctx, &storage.User{
		ID:        "user-rl",
		Email:     "rl@example.com",
		CreatedAt: now,
		UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	hash, _ := bcrypt.GenerateFromPassword([]byte("correctpw"), bcrypt.MinCost)
	_ = store.CreateCredential(ctx, &storage.Credential{
		ID:        "cred-rl",
		UserID:    "user-rl",
		Type:      "password",
		Secret:    hash,
		CreatedAt: now,
		UpdatedAt: now,
	})

	_ = store.CreateClient(ctx, &storage.Client{
		ID:           "rl-client",
		Name:         "RL Client",
		RedirectURIs: []string{"https://app.example.com/callback"},
		GrantTypes:   []string{"authorization_code"},
		Scopes:       []string{"openid"},
		PKCERequired: true,
		CreatedAt:    now,
		UpdatedAt:    now,
	})

	limiterCfg := config.RateLimitConfig{
		Enabled:          true,
		RequestsPerMin:   1000,
		LoginAttemptsMax: 2,
		LockoutDuration:  "1m",
	}
	limiter := ratelimit.NewLimiter(limiterCfg)
	defer limiter.Stop()

	sessCfg := session.Config{CookieName: "seki_session"}
	mgr := session.NewManager(store, sessCfg)

	signer := newTestSigner(t)
	provider := oidc.NewProvider("https://auth.example.com", signer, store,
		oidc.WithSessionManager(mgr),
		oidc.WithAuthenticationConfig(config.AuthenticationConfig{
			Password: config.PasswordConfig{Enabled: true},
		}),
		oidc.WithRateLimiter(limiter),
	)

	mux := http.NewServeMux()
	provider.RegisterRoutes(mux)

	// Fail login attempts to trigger lockout.
	for i := 0; i < 3; i++ {
		form := url.Values{
			"email":    {"rl@example.com"},
			"password": {"wrongpassword"},
		}
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "10.0.0.1:1234"
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
	}

	// Next attempt should be rate limited.
	form := url.Values{
		"email":    {"rl@example.com"},
		"password": {"correctpw"},
	}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "10.0.0.1:1234"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 (rate limited), got %d", rec.Code)
	}
}

func TestAuthorize_NoSessionManager(t *testing.T) {
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
	_ = store.CreateClient(ctx, &storage.Client{
		ID:           "no-sess-client",
		Name:         "No Sess",
		RedirectURIs: []string{"https://app.example.com/callback"},
		GrantTypes:   []string{"authorization_code"},
		Scopes:       []string{"openid"},
		PKCERequired: false,
		CreatedAt:    now,
		UpdatedAt:    now,
	})

	signer := newTestSigner(t)
	// Create provider WITHOUT session manager.
	provider := oidc.NewProvider("https://auth.example.com", signer, store)
	mux := http.NewServeMux()
	provider.RegisterRoutes(mux)

	params := url.Values{
		"client_id":     {"no-sess-client"},
		"redirect_uri":  {"https://app.example.com/callback"},
		"response_type": {"code"},
		"scope":         {"openid"},
	}

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rec.Code)
	}
	loc, _ := rec.Result().Location()
	if loc.Query().Get("error") != "login_required" {
		t.Errorf("expected login_required error, got %q", loc.Query().Get("error"))
	}
}

func TestToken_MissingCode(t *testing.T) {
	h := newTokenHarness(t)

	params := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
	}

	resp := h.doTokenRequest(t, params)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
	body := decodeTokenResponse(t, resp)
	if body["error"] != "invalid_request" {
		t.Errorf("error = %v, want invalid_request", body["error"])
	}
}

func TestToken_CodeClientMismatch(t *testing.T) {
	h := newTokenHarness(t)

	verifier := "mismatch-verifier"
	challenge := computeS256Challenge(verifier)

	// Code issued to test-client.
	h.createAuthCode(t, "mismatch-code", "test-client", "user-1",
		"https://app.example.com/callback", challenge, "",
		[]string{"openid"}, time.Now().Add(10*time.Minute))

	// But request claims to be public-client.
	params := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"mismatch-code"},
		"client_id":     {"public-client"},
		"code_verifier": {verifier},
	}

	resp := h.doTokenRequest(t, params)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
	body := decodeTokenResponse(t, resp)
	if body["error"] != "invalid_grant" {
		t.Errorf("error = %v, want invalid_grant", body["error"])
	}
}

func TestToken_RedirectURIMismatch(t *testing.T) {
	h := newTokenHarness(t)

	verifier := "redirect-mismatch-verifier"
	challenge := computeS256Challenge(verifier)

	h.createAuthCode(t, "redirect-code", "test-client", "user-1",
		"https://app.example.com/callback", challenge, "",
		[]string{"openid"}, time.Now().Add(10*time.Minute))

	params := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"redirect-code"},
		"redirect_uri":  {"https://wrong.example.com/callback"},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
		"code_verifier": {verifier},
	}

	resp := h.doTokenRequest(t, params)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestToken_PKCEMissingVerifier(t *testing.T) {
	h := newTokenHarness(t)

	challenge := computeS256Challenge("some-verifier")

	h.createAuthCode(t, "pkce-no-verifier", "test-client", "user-1",
		"https://app.example.com/callback", challenge, "",
		[]string{"openid"}, time.Now().Add(10*time.Minute))

	params := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"pkce-no-verifier"},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
		// No code_verifier.
	}

	resp := h.doTokenRequest(t, params)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
	body := decodeTokenResponse(t, resp)
	if body["error"] != "invalid_grant" {
		t.Errorf("error = %v", body["error"])
	}
}

func TestToken_ClientCredentials_Unauthorized(t *testing.T) {
	h := newTokenHarness(t)

	// test-client doesn't have client_credentials grant.
	params := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
	}

	resp := h.doTokenRequest(t, params)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
	body := decodeTokenResponse(t, resp)
	if body["error"] != "unauthorized_client" {
		t.Errorf("error = %v, want unauthorized_client", body["error"])
	}
}

func TestToken_RefreshToken_MissingToken(t *testing.T) {
	h := newTokenHarness(t)

	params := url.Values{
		"grant_type": {"refresh_token"},
	}

	resp := h.doTokenRequest(t, params)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestToken_RefreshToken_ClientMismatch(t *testing.T) {
	h := newTokenHarness(t)
	now := time.Now().UTC()

	rawToken := "rt-client-mismatch"
	tokenHash := hashForTest(rawToken)
	rt := &storage.RefreshToken{
		ID:        "rt-cm",
		TokenHash: tokenHash,
		ClientID:  "test-client",
		UserID:    "user-1",
		Scopes:    []string{"openid"},
		Family:    "family-cm",
		ExpiresAt: now.Add(30 * 24 * time.Hour),
		CreatedAt: now,
	}
	if err := h.store.CreateRefreshToken(context.Background(), rt); err != nil {
		t.Fatalf("create rt: %v", err)
	}

	params := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rawToken},
		"client_id":     {"public-client"}, // different client
	}

	resp := h.doTokenRequest(t, params)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
	body := decodeTokenResponse(t, resp)
	if body["error"] != "invalid_grant" {
		t.Errorf("error = %v", body["error"])
	}
}

func TestToken_RefreshToken_Expired(t *testing.T) {
	h := newTokenHarness(t)
	now := time.Now().UTC()

	rawToken := "rt-expired"
	tokenHash := hashForTest(rawToken)
	rt := &storage.RefreshToken{
		ID:        "rt-exp",
		TokenHash: tokenHash,
		ClientID:  "test-client",
		UserID:    "user-1",
		Scopes:    []string{"openid"},
		Family:    "family-exp",
		ExpiresAt: now.Add(-1 * time.Hour), // expired
		CreatedAt: now.Add(-2 * time.Hour),
	}
	if err := h.store.CreateRefreshToken(context.Background(), rt); err != nil {
		t.Fatalf("create rt: %v", err)
	}

	params := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rawToken},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
	}

	resp := h.doTokenRequest(t, params)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}
