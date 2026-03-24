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

	"github.com/entoten/seki/internal/config"
	"github.com/entoten/seki/internal/oidc"
	"github.com/entoten/seki/internal/session"
	"github.com/entoten/seki/internal/storage"

	_ "github.com/entoten/seki/internal/storage/sqlite"
)

// stepUpHarness extends the test harness with MFA-specific helpers.
type stepUpHarness struct {
	store    storage.Storage
	sessions *session.Manager
	provider *oidc.Provider
	mux      *http.ServeMux
	cookie   *http.Cookie
	sessID   string
}

func newStepUpHarness(t *testing.T, authnCfg config.AuthenticationConfig) *stepUpHarness {
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
	provider := oidc.NewProvider(
		"https://auth.example.com",
		signer,
		store,
		oidc.WithSessionManager(mgr),
		oidc.WithAuthenticationConfig(authnCfg),
	)

	mux := http.NewServeMux()
	provider.RegisterRoutes(mux)

	return &stepUpHarness{
		store:    store,
		sessions: mgr,
		provider: provider,
		mux:      mux,
		sessID:   sess.ID,
		cookie: &http.Cookie{
			Name:  "seki_session",
			Value: sess.ID,
		},
	}
}

func stepUpParams() url.Values {
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

func TestStepUp_ACRMFARedirectsToMFA(t *testing.T) {
	h := newStepUpHarness(t, config.AuthenticationConfig{})
	params := stepUpParams()
	params.Set("acr_values", "urn:seki:acr:mfa")

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil)
	req.AddCookie(h.cookie)
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", resp.StatusCode)
	}

	loc, err := resp.Location()
	if err != nil {
		t.Fatalf("no Location header: %v", err)
	}

	if loc.Path != "/mfa" {
		t.Errorf("expected redirect to /mfa, got %q", loc.Path)
	}

	// OIDC params should be preserved.
	if loc.Query().Get("client_id") != "test-client" {
		t.Errorf("client_id not preserved: %q", loc.Query().Get("client_id"))
	}
	if loc.Query().Get("acr_values") != "urn:seki:acr:mfa" {
		t.Errorf("acr_values not preserved: %q", loc.Query().Get("acr_values"))
	}
}

func TestStepUp_ACRMFAProceedsWhenVerified(t *testing.T) {
	h := newStepUpHarness(t, config.AuthenticationConfig{})

	// Mark session as MFA-verified.
	meta := map[string]interface{}{
		"mfa_verified":    true,
		"mfa_method":      "totp",
		"mfa_verified_at": time.Now().UTC().Format(time.RFC3339),
	}
	metaJSON, _ := json.Marshal(meta)
	err := h.sessions.UpdateMetadata(context.Background(), h.sessID, json.RawMessage(metaJSON))
	if err != nil {
		t.Fatalf("update session metadata: %v", err)
	}

	params := stepUpParams()
	params.Set("acr_values", "urn:seki:acr:mfa")

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil)
	req.AddCookie(h.cookie)
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", resp.StatusCode)
	}

	loc, err := resp.Location()
	if err != nil {
		t.Fatalf("no Location header: %v", err)
	}

	// Should redirect to client callback with code (not /mfa).
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatal("expected code in redirect, got none")
	}
	if loc.Host != "app.example.com" {
		t.Errorf("expected redirect to app.example.com, got %q", loc.Host)
	}
}

func TestStepUp_NoACRValuesWorksNormally(t *testing.T) {
	h := newStepUpHarness(t, config.AuthenticationConfig{})
	params := stepUpParams()
	// No acr_values parameter.

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil)
	req.AddCookie(h.cookie)
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)

	resp := rec.Result()
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
}

func TestStepUp_IDTokenIncludesACRBasic(t *testing.T) {
	h := newStepUpHarness(t, config.AuthenticationConfig{})
	params := stepUpParams()

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil)
	req.AddCookie(h.cookie)
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	loc, _ := resp.Location()
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatal("expected code")
	}

	// Verify auth code has basic ACR.
	ac, err := h.store.GetAuthCode(context.Background(), code)
	if err != nil {
		t.Fatalf("GetAuthCode: %v", err)
	}
	if ac.ACR != "urn:seki:acr:basic" {
		t.Errorf("ACR = %q, want urn:seki:acr:basic", ac.ACR)
	}
}

func TestStepUp_IDTokenIncludesACRMFA(t *testing.T) {
	h := newStepUpHarness(t, config.AuthenticationConfig{})

	// Mark session as MFA-verified.
	meta := map[string]interface{}{
		"mfa_verified":    true,
		"mfa_method":      "totp",
		"mfa_verified_at": time.Now().UTC().Format(time.RFC3339),
	}
	metaJSON, _ := json.Marshal(meta)
	err := h.sessions.UpdateMetadata(context.Background(), h.sessID, json.RawMessage(metaJSON))
	if err != nil {
		t.Fatalf("update session metadata: %v", err)
	}

	params := stepUpParams()
	params.Set("acr_values", "urn:seki:acr:mfa")

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil)
	req.AddCookie(h.cookie)
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	loc, _ := resp.Location()
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatal("expected code")
	}

	// Verify auth code has MFA ACR.
	ac, err := h.store.GetAuthCode(context.Background(), code)
	if err != nil {
		t.Fatalf("GetAuthCode: %v", err)
	}
	if ac.ACR != "urn:seki:acr:mfa" {
		t.Errorf("ACR = %q, want urn:seki:acr:mfa", ac.ACR)
	}
}

func TestStepUp_MFAPageRendersForAuthenticatedUser(t *testing.T) {
	h := newStepUpHarness(t, config.AuthenticationConfig{
		TOTP: config.TOTPConfig{Enabled: true},
	})

	// Create a TOTP credential for the user so the page shows the TOTP option.
	now := time.Now().UTC()
	err := h.store.CreateCredential(context.Background(), &storage.Credential{
		ID:        "cred-totp-1",
		UserID:    "user-1",
		Type:      "totp",
		Secret:    []byte("JBSWY3DPEHPK3PXP"),
		CreatedAt: now,
		UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("create totp credential: %v", err)
	}

	params := stepUpParams()
	params.Set("acr_values", "urn:seki:acr:mfa")

	req := httptest.NewRequest(http.MethodGet, "/mfa?"+params.Encode(), nil)
	req.AddCookie(h.cookie)
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "Additional Verification Required") {
		t.Error("MFA page missing title")
	}
	if !strings.Contains(body, "totp_code") {
		t.Error("MFA page missing TOTP code input")
	}
}

func TestStepUp_MFAPageRedirectsWithoutSession(t *testing.T) {
	h := newStepUpHarness(t, config.AuthenticationConfig{})

	req := httptest.NewRequest(http.MethodGet, "/mfa?client_id=test-client", nil)
	// No cookie.
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", resp.StatusCode)
	}

	loc, _ := resp.Location()
	if loc.Path != "/login" {
		t.Errorf("expected redirect to /login, got %q", loc.Path)
	}
}

func TestStepUp_MFASubmitUpdatesSession(t *testing.T) {
	h := newStepUpHarness(t, config.AuthenticationConfig{
		TOTP: config.TOTPConfig{Enabled: true},
	})

	// Create a TOTP credential. We use a known secret and generate a valid code.
	totpSecret := "JBSWY3DPEHPK3PXP"
	now := time.Now().UTC()
	err := h.store.CreateCredential(context.Background(), &storage.Credential{
		ID:        "cred-totp-1",
		UserID:    "user-1",
		Type:      "totp",
		Secret:    []byte(totpSecret),
		CreatedAt: now,
		UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("create totp credential: %v", err)
	}

	// Generate a valid TOTP code.
	validCode := generateTestTOTPCode(t, totpSecret)

	form := url.Values{
		"mfa_method": {"totp"},
		"totp_code":  {validCode},
		"client_id":  {"test-client"},
	}

	req := httptest.NewRequest(http.MethodPost, "/mfa", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(h.cookie)
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 redirect, got %d", resp.StatusCode)
	}

	loc, _ := resp.Location()
	if loc.Path != "/authorize" {
		t.Errorf("expected redirect to /authorize, got %q", loc.Path)
	}

	// Verify session metadata was updated.
	sess, err := h.sessions.Get(context.Background(), h.sessID)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}

	var meta map[string]interface{}
	if err := json.Unmarshal(sess.Metadata, &meta); err != nil {
		t.Fatalf("unmarshal metadata: %v", err)
	}

	mfaVerified, ok := meta["mfa_verified"].(bool)
	if !ok || !mfaVerified {
		t.Error("session metadata mfa_verified should be true")
	}
	mfaMethod, ok := meta["mfa_method"].(string)
	if !ok || mfaMethod != "totp" {
		t.Errorf("mfa_method = %q, want totp", mfaMethod)
	}
	if _, ok := meta["mfa_verified_at"].(string); !ok {
		t.Error("mfa_verified_at should be set")
	}
}

// generateTestTOTPCode generates a valid TOTP code for testing using the pquerna/otp library.
func generateTestTOTPCode(t *testing.T, secret string) string {
	t.Helper()
	// Use the same TOTP library as the production code to generate a valid code.
	code, err := generateTOTPCodeHelper(secret, time.Now())
	if err != nil {
		t.Fatalf("generate TOTP code: %v", err)
	}
	return code
}
