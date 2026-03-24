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

	"crypto/ed25519"
	crand "crypto/rand"

	"github.com/entoten/seki/internal/crypto"
	"github.com/entoten/seki/internal/oidc"
	"github.com/entoten/seki/internal/session"
	"github.com/entoten/seki/internal/storage"

	_ "github.com/entoten/seki/internal/storage/sqlite"
)

type deviceHarness struct {
	store    storage.Storage
	provider *oidc.Provider
	mux      *http.ServeMux
	sessions *session.Manager
}

func newDeviceHarness(t *testing.T) *deviceHarness {
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

	// Create test user.
	err = store.CreateUser(ctx, &storage.User{
		ID:        "user-1",
		Email:     "test@example.com",
		CreatedAt: now,
		UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	// Create test client.
	err = store.CreateClient(ctx, &storage.Client{
		ID:           "device-client",
		Name:         "Device Client",
		RedirectURIs: []string{},
		GrantTypes:   []string{"urn:ietf:params:oauth:grant-type:device_code"},
		Scopes:       []string{"openid", "profile"},
		CreatedAt:    now,
		UpdatedAt:    now,
	})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	_, priv, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer := crypto.NewEd25519SignerFromKey(priv, "test-key", "http://localhost", 15*time.Minute)

	sessMgr := session.NewManager(store, session.Config{
		CookieName:      "seki_session",
		IdleTimeout:     30 * time.Minute,
		AbsoluteTimeout: 24 * time.Hour,
	})

	provider := oidc.NewProvider("http://localhost", signer, store,
		oidc.WithSessionManager(sessMgr),
	)

	mux := http.NewServeMux()
	provider.RegisterRoutes(mux)

	return &deviceHarness{
		store:    store,
		provider: provider,
		mux:      mux,
		sessions: sessMgr,
	}
}

func TestDeviceCodeIssuance(t *testing.T) {
	h := newDeviceHarness(t)

	form := url.Values{}
	form.Set("client_id", "device-client")
	form.Set("scope", "openid profile")

	req := httptest.NewRequest(http.MethodPost, "/device/code", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	// Check required fields.
	for _, field := range []string{"device_code", "user_code", "verification_uri", "verification_uri_complete", "expires_in", "interval"} {
		if _, ok := resp[field]; !ok {
			t.Fatalf("missing field %q in response", field)
		}
	}

	userCode, ok := resp["user_code"].(string)
	if !ok || len(userCode) != 8 {
		t.Fatalf("user_code should be 8 chars, got %q", resp["user_code"])
	}

	// Verify user_code uses only valid alphabet (no 0, O, I, L).
	for _, c := range userCode {
		if c == '0' || c == 'O' || c == 'I' || c == 'L' {
			t.Fatalf("user_code contains forbidden character: %c", c)
		}
	}

	interval, ok := resp["interval"].(float64)
	if !ok || interval != 5 {
		t.Fatalf("expected interval 5, got %v", resp["interval"])
	}
}

func TestDeviceCodeInvalidClient(t *testing.T) {
	h := newDeviceHarness(t)

	form := url.Values{}
	form.Set("client_id", "nonexistent")

	req := httptest.NewRequest(http.MethodPost, "/device/code", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestDeviceCodeMissingClientID(t *testing.T) {
	h := newDeviceHarness(t)

	req := httptest.NewRequest(http.MethodPost, "/device/code", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestDevicePageRendering(t *testing.T) {
	h := newDeviceHarness(t)

	req := httptest.NewRequest(http.MethodGet, "/device", nil)
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Fatalf("expected text/html content type, got %s", ct)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "Device Authorization") {
		t.Fatal("page should contain 'Device Authorization'")
	}
}

func TestTokenPollingAuthorizationPending(t *testing.T) {
	h := newDeviceHarness(t)

	// Issue device code.
	form := url.Values{}
	form.Set("client_id", "device-client")
	req := httptest.NewRequest(http.MethodPost, "/device/code", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)

	var issueResp map[string]interface{}
	_ = json.NewDecoder(rec.Body).Decode(&issueResp)
	deviceCode := issueResp["device_code"].(string)

	// Poll token endpoint — should get authorization_pending.
	tokenForm := url.Values{}
	tokenForm.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	tokenForm.Set("device_code", deviceCode)
	tokenForm.Set("client_id", "device-client")

	req = httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(tokenForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}

	var errResp map[string]string
	_ = json.NewDecoder(rec.Body).Decode(&errResp)
	if errResp["error"] != "authorization_pending" {
		t.Fatalf("expected authorization_pending, got %s", errResp["error"])
	}
}

func TestTokenPollingAfterApproval(t *testing.T) {
	h := newDeviceHarness(t)
	ctx := context.Background()

	// Issue device code.
	form := url.Values{}
	form.Set("client_id", "device-client")
	req := httptest.NewRequest(http.MethodPost, "/device/code", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)

	var issueResp map[string]interface{}
	_ = json.NewDecoder(rec.Body).Decode(&issueResp)
	deviceCode := issueResp["device_code"].(string)

	// Simulate user approval directly in the store.
	err := h.store.UpdateDeviceCodeStatus(ctx, deviceCode, "approved", "user-1")
	if err != nil {
		t.Fatalf("approve device code: %v", err)
	}

	// Poll token endpoint — should get tokens.
	tokenForm := url.Values{}
	tokenForm.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	tokenForm.Set("device_code", deviceCode)
	tokenForm.Set("client_id", "device-client")

	req = httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(tokenForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var tokenResp map[string]interface{}
	_ = json.NewDecoder(rec.Body).Decode(&tokenResp)
	if _, ok := tokenResp["access_token"]; !ok {
		t.Fatal("response should contain access_token")
	}
	if _, ok := tokenResp["refresh_token"]; !ok {
		t.Fatal("response should contain refresh_token")
	}
}

func TestExpiredDeviceCodeReturnsExpiredToken(t *testing.T) {
	h := newDeviceHarness(t)
	ctx := context.Background()

	// Create an expired device code directly.
	now := time.Now().UTC().Truncate(time.Second)
	dc := &storage.DeviceCode{
		DeviceCode: "expired-dc",
		UserCode:   "ABCD1234",
		ClientID:   "device-client",
		Scopes:     []string{"openid"},
		Status:     "pending",
		ExpiresAt:  now.Add(-1 * time.Hour),
		Interval:   5,
		CreatedAt:  now.Add(-2 * time.Hour),
	}
	if err := h.store.CreateDeviceCode(ctx, dc); err != nil {
		t.Fatalf("create expired device code: %v", err)
	}

	tokenForm := url.Values{}
	tokenForm.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	tokenForm.Set("device_code", "expired-dc")
	tokenForm.Set("client_id", "device-client")

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(tokenForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}

	var errResp map[string]string
	_ = json.NewDecoder(rec.Body).Decode(&errResp)
	if errResp["error"] != "expired_token" {
		t.Fatalf("expected expired_token, got %s", errResp["error"])
	}
}

func TestDeniedDeviceCodeReturnsAccessDenied(t *testing.T) {
	h := newDeviceHarness(t)
	ctx := context.Background()

	// Issue device code.
	form := url.Values{}
	form.Set("client_id", "device-client")
	req := httptest.NewRequest(http.MethodPost, "/device/code", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)

	var issueResp map[string]interface{}
	_ = json.NewDecoder(rec.Body).Decode(&issueResp)
	deviceCode := issueResp["device_code"].(string)

	// Deny.
	err := h.store.UpdateDeviceCodeStatus(ctx, deviceCode, "denied", "user-1")
	if err != nil {
		t.Fatalf("deny device code: %v", err)
	}

	tokenForm := url.Values{}
	tokenForm.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	tokenForm.Set("device_code", deviceCode)
	tokenForm.Set("client_id", "device-client")

	req = httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(tokenForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}

	var errResp map[string]string
	_ = json.NewDecoder(rec.Body).Decode(&errResp)
	if errResp["error"] != "access_denied" {
		t.Fatalf("expected access_denied, got %s", errResp["error"])
	}
}
