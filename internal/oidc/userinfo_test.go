package oidc_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Monet/seki/internal/oidc"
	"github.com/Monet/seki/internal/storage"

	_ "github.com/Monet/seki/internal/storage/sqlite"
)

// userinfoHarness sets up the provider, store, and signer for userinfo tests.
type userinfoHarness struct {
	store    storage.Storage
	provider *oidc.Provider
	mux      *http.ServeMux
	signer   interface {
		Sign(claims map[string]interface{}) (string, error)
	}
}

func newUserinfoHarness(t *testing.T) *userinfoHarness {
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

	err = store.CreateUser(ctx, &storage.User{
		ID:          "user-1",
		Email:       "alice@example.com",
		DisplayName: "Alice Smith",
		CreatedAt:   now,
		UpdatedAt:   now,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	signer := newTestSigner(t)
	provider := oidc.NewProvider("https://auth.example.com", signer, store)

	mux := http.NewServeMux()
	provider.RegisterRoutes(mux)

	return &userinfoHarness{
		store:    store,
		provider: provider,
		mux:      mux,
		signer:   signer,
	}
}

func (h *userinfoHarness) makeAccessToken(t *testing.T, sub string, scopes []string, exp time.Time) string {
	t.Helper()
	now := time.Now().UTC()
	claims := map[string]interface{}{
		"sub":   sub,
		"aud":   "test-client",
		"scope": strings.Join(scopes, " "),
		"iat":   now.Unix(),
		"exp":   exp.Unix(),
		"iss":   "https://auth.example.com",
		"typ":   "access_token",
	}
	token, err := h.signer.Sign(claims)
	if err != nil {
		t.Fatalf("sign access token: %v", err)
	}
	return token
}

func TestUserInfo_ValidToken_OpenIDScope(t *testing.T) {
	h := newUserinfoHarness(t)

	token := h.makeAccessToken(t, "user-1", []string{"openid"}, time.Now().Add(10*time.Minute))

	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Fatalf("expected Content-Type application/json, got %s", ct)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if body["sub"] != "user-1" {
		t.Errorf("expected sub=user-1, got %v", body["sub"])
	}

	// openid scope alone should not include email or name.
	if _, ok := body["email"]; ok {
		t.Error("unexpected email claim with only openid scope")
	}
	if _, ok := body["name"]; ok {
		t.Error("unexpected name claim with only openid scope")
	}
}

func TestUserInfo_EmailScope(t *testing.T) {
	h := newUserinfoHarness(t)

	token := h.makeAccessToken(t, "user-1", []string{"openid", "email"}, time.Now().Add(10*time.Minute))

	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if body["email"] != "alice@example.com" {
		t.Errorf("expected email=alice@example.com, got %v", body["email"])
	}
	if body["email_verified"] != true {
		t.Errorf("expected email_verified=true, got %v", body["email_verified"])
	}
}

func TestUserInfo_ProfileScope(t *testing.T) {
	h := newUserinfoHarness(t)

	token := h.makeAccessToken(t, "user-1", []string{"openid", "profile"}, time.Now().Add(10*time.Minute))

	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if body["name"] != "Alice Smith" {
		t.Errorf("expected name=Alice Smith, got %v", body["name"])
	}
	if body["preferred_username"] != "user-1" {
		t.Errorf("expected preferred_username=user-1, got %v", body["preferred_username"])
	}
}

func TestUserInfo_MissingAuthorizationHeader(t *testing.T) {
	h := newUserinfoHarness(t)

	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestUserInfo_InvalidToken(t *testing.T) {
	h := newUserinfoHarness(t)

	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer invalid.jwt.token")
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestUserInfo_ExpiredToken(t *testing.T) {
	h := newUserinfoHarness(t)

	// Token that expired 10 minutes ago.
	token := h.makeAccessToken(t, "user-1", []string{"openid"}, time.Now().Add(-10*time.Minute))

	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestUserInfo_NonExistentUser(t *testing.T) {
	h := newUserinfoHarness(t)

	// Token for a user that does not exist in the store.
	token := h.makeAccessToken(t, "no-such-user", []string{"openid"}, time.Now().Add(10*time.Minute))

	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}
