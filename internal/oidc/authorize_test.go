package oidc_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/entoten/seki/internal/oidc"
	"github.com/entoten/seki/internal/session"
	"github.com/entoten/seki/internal/storage"

	_ "github.com/entoten/seki/internal/storage/sqlite"
)

// testHarness holds common test fixtures for authorize tests.
type testHarness struct {
	store    storage.Storage
	sessions *session.Manager
	provider *oidc.Provider
	mux      *http.ServeMux
	cookie   *http.Cookie
}

func newTestHarness(t *testing.T) *testHarness {
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
		ID:        "user-1",
		Email:     "test@example.com",
		CreatedAt: now,
		UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	// Create a test client.
	err = store.CreateClient(ctx, &storage.Client{
		ID:           "test-client",
		Name:         "Test Client",
		RedirectURIs: []string{"https://app.example.com/callback"},
		GrantTypes:   []string{"authorization_code"},
		Scopes:       []string{"openid", "profile", "email"},
		PKCERequired: true,
		CreatedAt:    now,
		UpdatedAt:    now,
	})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	// Create session manager and a session.
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

	return &testHarness{
		store:    store,
		sessions: mgr,
		provider: provider,
		mux:      mux,
		cookie: &http.Cookie{
			Name:  "seki_session",
			Value: sess.ID,
		},
	}
}

func (h *testHarness) doAuthorize(t *testing.T, params url.Values, withCookie bool) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil)
	if withCookie {
		req.AddCookie(h.cookie)
	}
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)
	return rec.Result()
}

func validParams() url.Values {
	return url.Values{
		"client_id":             {"test-client"},
		"redirect_uri":          {"https://app.example.com/callback"},
		"response_type":         {"code"},
		"scope":                 {"openid profile"},
		"state":                 {"test-state"},
		"code_challenge":        {"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"},
		"code_challenge_method": {"S256"},
	}
}

func TestAuthorize_ValidRequest(t *testing.T) {
	h := newTestHarness(t)
	resp := h.doAuthorize(t, validParams(), true)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", resp.StatusCode)
	}

	loc, err := resp.Location()
	if err != nil {
		t.Fatalf("no Location header: %v", err)
	}

	code := loc.Query().Get("code")
	if code == "" {
		t.Fatal("expected code in redirect, got none")
	}
	if loc.Query().Get("state") != "test-state" {
		t.Errorf("state = %q, want test-state", loc.Query().Get("state"))
	}

	// Verify code is stored in DB.
	ac, err := h.store.GetAuthCode(context.Background(), code)
	if err != nil {
		t.Fatalf("GetAuthCode: %v", err)
	}
	if ac.ClientID != "test-client" {
		t.Errorf("auth code client_id = %q, want test-client", ac.ClientID)
	}
	if ac.UserID != "user-1" {
		t.Errorf("auth code user_id = %q, want user-1", ac.UserID)
	}
	if ac.RedirectURI != "https://app.example.com/callback" {
		t.Errorf("auth code redirect_uri = %q", ac.RedirectURI)
	}
	if ac.CodeChallenge != "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" {
		t.Errorf("auth code code_challenge = %q", ac.CodeChallenge)
	}
	if ac.CodeChallengeMethod != "S256" {
		t.Errorf("auth code code_challenge_method = %q", ac.CodeChallengeMethod)
	}
}

func TestAuthorize_MissingClientID(t *testing.T) {
	h := newTestHarness(t)
	params := validParams()
	params.Del("client_id")
	resp := h.doAuthorize(t, params, true)
	defer resp.Body.Close()

	// Should render error page (not redirect).
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestAuthorize_UnknownClientID(t *testing.T) {
	h := newTestHarness(t)
	params := validParams()
	params.Set("client_id", "unknown-client")
	resp := h.doAuthorize(t, params, true)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestAuthorize_InvalidRedirectURI(t *testing.T) {
	h := newTestHarness(t)
	params := validParams()
	params.Set("redirect_uri", "https://evil.example.com/callback")
	resp := h.doAuthorize(t, params, true)
	defer resp.Body.Close()

	// Should render error page, NOT redirect to the invalid URI.
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
	// Must not have Location header pointing to the bad URI.
	if loc := resp.Header.Get("Location"); loc != "" {
		t.Fatalf("should not redirect to unvalidated URI, got Location: %s", loc)
	}
}

func TestAuthorize_MissingRedirectURI(t *testing.T) {
	h := newTestHarness(t)
	params := validParams()
	params.Del("redirect_uri")
	resp := h.doAuthorize(t, params, true)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestAuthorize_MissingResponseType(t *testing.T) {
	h := newTestHarness(t)
	params := validParams()
	params.Del("response_type")
	resp := h.doAuthorize(t, params, true)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", resp.StatusCode)
	}
	loc, _ := resp.Location()
	if loc.Query().Get("error") != "invalid_request" {
		t.Errorf("error = %q, want invalid_request", loc.Query().Get("error"))
	}
}

func TestAuthorize_UnsupportedResponseType(t *testing.T) {
	h := newTestHarness(t)
	params := validParams()
	params.Set("response_type", "token")
	resp := h.doAuthorize(t, params, true)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", resp.StatusCode)
	}
	loc, _ := resp.Location()
	if loc.Query().Get("error") != "unsupported_response_type" {
		t.Errorf("error = %q, want unsupported_response_type", loc.Query().Get("error"))
	}
}

func TestAuthorize_MissingScopeOpenID(t *testing.T) {
	h := newTestHarness(t)
	params := validParams()
	params.Set("scope", "profile email")
	resp := h.doAuthorize(t, params, true)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", resp.StatusCode)
	}
	loc, _ := resp.Location()
	if loc.Query().Get("error") != "invalid_scope" {
		t.Errorf("error = %q, want invalid_scope", loc.Query().Get("error"))
	}
}

func TestAuthorize_MissingCodeChallenge(t *testing.T) {
	h := newTestHarness(t)
	params := validParams()
	params.Del("code_challenge")
	params.Del("code_challenge_method")
	resp := h.doAuthorize(t, params, true)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", resp.StatusCode)
	}
	loc, _ := resp.Location()
	if loc.Query().Get("error") != "invalid_request" {
		t.Errorf("error = %q, want invalid_request", loc.Query().Get("error"))
	}
}

func TestAuthorize_InvalidCodeChallengeMethod(t *testing.T) {
	h := newTestHarness(t)
	params := validParams()
	params.Set("code_challenge_method", "plain")
	resp := h.doAuthorize(t, params, true)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", resp.StatusCode)
	}
	loc, _ := resp.Location()
	if loc.Query().Get("error") != "invalid_request" {
		t.Errorf("error = %q, want invalid_request", loc.Query().Get("error"))
	}
}

func TestAuthorize_NoSession(t *testing.T) {
	h := newTestHarness(t)
	resp := h.doAuthorize(t, validParams(), false)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", resp.StatusCode)
	}
	loc, _ := resp.Location()
	// Should redirect to /login with OIDC params preserved.
	if loc.Path != "/login" {
		t.Errorf("expected redirect to /login, got %q", loc.Path)
	}
	if loc.Query().Get("client_id") != "test-client" {
		t.Errorf("client_id not preserved in login redirect: %q", loc.Query().Get("client_id"))
	}
}

func TestAuthorize_AuthCodeExpiry(t *testing.T) {
	h := newTestHarness(t)
	resp := h.doAuthorize(t, validParams(), true)
	defer resp.Body.Close()

	loc, _ := resp.Location()
	code := loc.Query().Get("code")

	ac, err := h.store.GetAuthCode(context.Background(), code)
	if err != nil {
		t.Fatalf("GetAuthCode: %v", err)
	}

	// Auth code should expire within a reasonable TTL window.
	if ac.ExpiresAt.Before(time.Now()) {
		t.Error("auth code already expired")
	}
	if ac.ExpiresAt.After(time.Now().Add(15 * time.Minute)) {
		t.Error("auth code expires too far in the future")
	}
}

func TestAuthorize_StatePreserved(t *testing.T) {
	h := newTestHarness(t)
	params := validParams()
	params.Set("state", "my-unique-state-123")
	resp := h.doAuthorize(t, params, true)
	defer resp.Body.Close()

	loc, _ := resp.Location()
	if loc.Query().Get("state") != "my-unique-state-123" {
		t.Errorf("state = %q, want my-unique-state-123", loc.Query().Get("state"))
	}
}

func TestAuthorize_NoStateOmitted(t *testing.T) {
	h := newTestHarness(t)
	params := validParams()
	params.Del("state")
	resp := h.doAuthorize(t, params, true)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", resp.StatusCode)
	}
	loc, _ := resp.Location()
	// Code should be present.
	if loc.Query().Get("code") == "" {
		t.Fatal("expected code in redirect")
	}
	// State should not be set when not provided.
	if loc.Query().Get("state") != "" {
		t.Errorf("state should be empty when not provided, got %q", loc.Query().Get("state"))
	}
}

func TestAuthorize_CodeStoredAndRetrievable(t *testing.T) {
	h := newTestHarness(t)
	resp := h.doAuthorize(t, validParams(), true)
	defer resp.Body.Close()

	loc, _ := resp.Location()
	code := loc.Query().Get("code")

	// Retrieve the code.
	ac, err := h.store.GetAuthCode(context.Background(), code)
	if err != nil {
		t.Fatalf("GetAuthCode: %v", err)
	}
	if ac.Code != code {
		t.Errorf("code mismatch: got %q, want %q", ac.Code, code)
	}

	// Delete the code.
	err = h.store.DeleteAuthCode(context.Background(), code)
	if err != nil {
		t.Fatalf("DeleteAuthCode: %v", err)
	}

	// Should be gone now.
	_, err = h.store.GetAuthCode(context.Background(), code)
	if err != storage.ErrNotFound {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
}
