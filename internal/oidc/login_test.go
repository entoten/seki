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
	"github.com/entoten/seki/internal/session"
	"github.com/entoten/seki/internal/storage"
	_ "github.com/entoten/seki/internal/storage/sqlite"
)

// loginTestHarness extends testHarness with authentication config.
type loginTestHarness struct {
	store    storage.Storage
	sessions *session.Manager
	provider *oidc.Provider
	mux      *http.ServeMux
}

func newLoginTestHarness(t *testing.T, authnCfg config.AuthenticationConfig) *loginTestHarness {
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

	sessCfg := session.Config{CookieName: "seki_session"}
	mgr := session.NewManager(store, sessCfg)

	signer := newTestSigner(t)
	provider := oidc.NewProvider("https://auth.example.com", signer, store,
		oidc.WithSessionManager(mgr),
		oidc.WithAuthenticationConfig(authnCfg),
	)

	mux := http.NewServeMux()
	provider.RegisterRoutes(mux)

	return &loginTestHarness{
		store:    store,
		sessions: mgr,
		provider: provider,
		mux:      mux,
	}
}

func TestLoginPage_Renders(t *testing.T) {
	h := newLoginTestHarness(t, config.AuthenticationConfig{
		Passkey:  config.PasskeyConfig{Enabled: true},
		TOTP:     config.TOTPConfig{Enabled: true},
		Password: config.PasswordConfig{Enabled: true},
	})

	req := httptest.NewRequest(http.MethodGet, "/login?client_id=test-client&redirect_uri=https://app.example.com/callback", nil)
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)

	resp := rec.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	html := string(body)

	if !strings.Contains(html, "Sign In") {
		t.Error("login page should contain 'Sign In' heading")
	}
	ct := resp.Header.Get("Content-Type")
	if ct != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q, want text/html; charset=utf-8", ct)
	}
}

func TestLoginPage_ShowsPasskeyWhenEnabled(t *testing.T) {
	h := newLoginTestHarness(t, config.AuthenticationConfig{
		Passkey: config.PasskeyConfig{Enabled: true},
	})

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)

	body, _ := io.ReadAll(rec.Result().Body)
	if !strings.Contains(string(body), "Sign in with Passkey") {
		t.Error("login page should show passkey button when enabled")
	}
}

func TestLoginPage_HidesPasswordWhenDisabled(t *testing.T) {
	h := newLoginTestHarness(t, config.AuthenticationConfig{
		Passkey:  config.PasskeyConfig{Enabled: true},
		Password: config.PasswordConfig{Enabled: false},
	})

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)

	body, _ := io.ReadAll(rec.Result().Body)
	if strings.Contains(string(body), "sign in with password") {
		t.Error("login page should not show password form when disabled")
	}
}

func TestLoginPage_PreservesOIDCParams(t *testing.T) {
	h := newLoginTestHarness(t, config.AuthenticationConfig{
		Passkey: config.PasskeyConfig{Enabled: true},
	})

	req := httptest.NewRequest(http.MethodGet, "/login?client_id=test-client&redirect_uri=https://app.example.com/callback&state=abc123", nil)
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)

	body, _ := io.ReadAll(rec.Result().Body)
	html := string(body)

	if !strings.Contains(html, `name="client_id"`) {
		t.Error("login page should contain hidden client_id field")
	}
	if !strings.Contains(html, `value="test-client"`) {
		t.Error("login page should preserve client_id value")
	}
	if !strings.Contains(html, `value="abc123"`) {
		t.Error("login page should preserve state value")
	}
}

func TestLoginPage_ShowsSocialProviders(t *testing.T) {
	h := newLoginTestHarness(t, config.AuthenticationConfig{
		Social: map[string]config.SocialProvider{
			"google": {ClientID: "goog-id", ClientSecret: "goog-secret"},
			"github": {ClientID: "gh-id", ClientSecret: "gh-secret"},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)

	body, _ := io.ReadAll(rec.Result().Body)
	html := string(body)

	if !strings.Contains(html, "Sign in with google") && !strings.Contains(html, "Sign in with github") {
		t.Error("login page should show social provider buttons")
	}
}

func TestPasswordLogin_Success(t *testing.T) {
	h := newLoginTestHarness(t, config.AuthenticationConfig{
		Password: config.PasswordConfig{Enabled: true},
	})

	// Create a password credential for the test user.
	hash, err := bcrypt.GenerateFromPassword([]byte("correctpassword"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	err = h.store.CreateCredential(context.Background(), &storage.Credential{
		ID:        "cred-pw-1",
		UserID:    "user-1",
		Type:      "password",
		Secret:    hash,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("create credential: %v", err)
	}

	form := url.Values{
		"email":                 {"test@example.com"},
		"password":              {"correctpassword"},
		"client_id":             {"test-client"},
		"redirect_uri":          {"https://app.example.com/callback"},
		"response_type":         {"code"},
		"scope":                 {"openid"},
		"state":                 {"test-state"},
		"code_challenge":        {"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"},
		"code_challenge_method": {"S256"},
	}

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)

	resp := rec.Result()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", resp.StatusCode)
	}

	loc, err := resp.Location()
	if err != nil {
		t.Fatalf("no Location header: %v", err)
	}

	// Should redirect to /authorize with OIDC params.
	if loc.Path != "/authorize" {
		t.Errorf("expected redirect to /authorize, got %q", loc.Path)
	}
	if loc.Query().Get("client_id") != "test-client" {
		t.Errorf("client_id not preserved: %q", loc.Query().Get("client_id"))
	}
	if loc.Query().Get("state") != "test-state" {
		t.Errorf("state not preserved: %q", loc.Query().Get("state"))
	}

	// Should have a session cookie.
	cookies := resp.Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == "seki_session" && c.Value != "" {
			found = true
		}
	}
	if !found {
		t.Error("expected seki_session cookie to be set")
	}
}

func TestPasswordLogin_WrongPassword(t *testing.T) {
	h := newLoginTestHarness(t, config.AuthenticationConfig{
		Password: config.PasswordConfig{Enabled: true},
	})

	hash, _ := bcrypt.GenerateFromPassword([]byte("correctpassword"), bcrypt.DefaultCost)
	_ = h.store.CreateCredential(context.Background(), &storage.Credential{
		ID:        "cred-pw-1",
		UserID:    "user-1",
		Type:      "password",
		Secret:    hash,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	})

	form := url.Values{
		"email":    {"test@example.com"},
		"password": {"wrongpassword"},
	}

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)

	resp := rec.Result()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Invalid email or password") {
		t.Error("should show invalid credentials error")
	}
}

func TestLogout_DestroysSessionAndClearsCookie(t *testing.T) {
	h := newLoginTestHarness(t, config.AuthenticationConfig{})

	// Create a session.
	sess, err := h.sessions.Create(context.Background(), "user-1", "", "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(&http.Cookie{Name: "seki_session", Value: sess.ID})
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)

	resp := rec.Result()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", resp.StatusCode)
	}

	// Cookie should be cleared (MaxAge = -1).
	cookies := resp.Cookies()
	cleared := false
	for _, c := range cookies {
		if c.Name == "seki_session" && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("expected session cookie to be cleared")
	}

	// Session should be deleted from store.
	_, err = h.sessions.Get(context.Background(), sess.ID)
	if err == nil {
		t.Error("expected session to be deleted after logout")
	}
}

func TestLoginFlow_EndToEnd(t *testing.T) {
	// Tests the full flow: /authorize -> /login -> POST /login -> /authorize -> code
	h := newLoginTestHarness(t, config.AuthenticationConfig{
		Password: config.PasswordConfig{Enabled: true},
	})

	hash, _ := bcrypt.GenerateFromPassword([]byte("testpass"), bcrypt.DefaultCost)
	_ = h.store.CreateCredential(context.Background(), &storage.Credential{
		ID:        "cred-pw-1",
		UserID:    "user-1",
		Type:      "password",
		Secret:    hash,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	})

	params := validParams()

	// Step 1: Hit /authorize without session -> redirects to /login.
	req1 := httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil)
	rec1 := httptest.NewRecorder()
	h.mux.ServeHTTP(rec1, req1)

	resp1 := rec1.Result()
	if resp1.StatusCode != http.StatusFound {
		t.Fatalf("step1: expected 302, got %d", resp1.StatusCode)
	}
	loginLoc, _ := resp1.Location()
	if loginLoc.Path != "/login" {
		t.Fatalf("step1: expected redirect to /login, got %q", loginLoc.Path)
	}

	// Step 2: POST /login with valid credentials and OIDC params.
	form := url.Values{
		"email":    {"test@example.com"},
		"password": {"testpass"},
	}
	// Copy OIDC params from the login redirect.
	for _, k := range []string{"client_id", "redirect_uri", "response_type", "scope", "state", "code_challenge", "code_challenge_method"} {
		if v := loginLoc.Query().Get(k); v != "" {
			form.Set(k, v)
		}
	}

	req2 := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec2 := httptest.NewRecorder()
	h.mux.ServeHTTP(rec2, req2)

	resp2 := rec2.Result()
	if resp2.StatusCode != http.StatusFound {
		t.Fatalf("step2: expected 302, got %d", resp2.StatusCode)
	}
	authLoc, _ := resp2.Location()
	if authLoc.Path != "/authorize" {
		t.Fatalf("step2: expected redirect to /authorize, got %q", authLoc.Path)
	}

	// Extract the session cookie.
	var sessionCookie *http.Cookie
	for _, c := range resp2.Cookies() {
		if c.Name == "seki_session" {
			sessionCookie = c
		}
	}
	if sessionCookie == nil {
		t.Fatal("step2: expected session cookie")
	}

	// Step 3: Hit /authorize again WITH session -> should get code redirect.
	req3 := httptest.NewRequest(http.MethodGet, authLoc.RequestURI(), nil)
	req3.AddCookie(sessionCookie)
	rec3 := httptest.NewRecorder()
	h.mux.ServeHTTP(rec3, req3)

	resp3 := rec3.Result()
	if resp3.StatusCode != http.StatusFound {
		t.Fatalf("step3: expected 302, got %d", resp3.StatusCode)
	}
	callbackLoc, _ := resp3.Location()
	code := callbackLoc.Query().Get("code")
	if code == "" {
		t.Fatal("step3: expected authorization code in redirect")
	}
	if callbackLoc.Query().Get("state") != params.Get("state") {
		t.Errorf("step3: state = %q, want %q", callbackLoc.Query().Get("state"), params.Get("state"))
	}
}
