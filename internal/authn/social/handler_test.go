package social

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Monet/seki/internal/config"
)

func TestHandlerAuthorize(t *testing.T) {
	cfg := map[string]config.SocialProvider{
		"google": {ClientID: "gid", ClientSecret: "gsecret"},
	}
	svc := NewService(cfg, nil)
	h := NewHandler(svc, "https://example.com")

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/authn/social/google/authorize", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d: %s", rec.Code, rec.Body.String())
	}

	loc := rec.Header().Get("Location")
	if loc == "" {
		t.Fatal("expected Location header")
	}

	// Check state cookie is set.
	cookies := rec.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == "oauth_state" && c.Value != "" {
			found = true
		}
	}
	if !found {
		t.Error("expected oauth_state cookie")
	}
}

func TestHandlerAuthorize_UnknownProvider(t *testing.T) {
	cfg := map[string]config.SocialProvider{
		"google": {ClientID: "gid", ClientSecret: "gsecret"},
	}
	svc := NewService(cfg, nil)
	h := NewHandler(svc, "https://example.com")

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/authn/social/twitter/authorize", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestHandlerCallback_MissingStateCookie(t *testing.T) {
	cfg := map[string]config.SocialProvider{
		"google": {ClientID: "gid", ClientSecret: "gsecret"},
	}
	svc := NewService(cfg, nil)
	h := NewHandler(svc, "https://example.com")

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/authn/social/google/callback?code=abc&state=xyz", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}

	var resp map[string]string
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if resp["error"] != "missing state cookie" {
		t.Errorf("error = %q", resp["error"])
	}
}

func TestHandlerCallback_StateMismatch(t *testing.T) {
	cfg := map[string]config.SocialProvider{
		"google": {ClientID: "gid", ClientSecret: "gsecret"},
	}
	svc := NewService(cfg, nil)
	h := NewHandler(svc, "https://example.com")

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/authn/social/google/callback?code=abc&state=wrong", nil)
	req.AddCookie(&http.Cookie{Name: "oauth_state", Value: "correct"})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestHandlerCallback_MissingCode(t *testing.T) {
	cfg := map[string]config.SocialProvider{
		"google": {ClientID: "gid", ClientSecret: "gsecret"},
	}
	svc := NewService(cfg, nil)
	h := NewHandler(svc, "https://example.com")

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/authn/social/google/callback?state=abc", nil)
	req.AddCookie(&http.Cookie{Name: "oauth_state", Value: "abc"})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestGenerateState(t *testing.T) {
	s1, err := generateState()
	if err != nil {
		t.Fatalf("generateState: %v", err)
	}
	s2, err := generateState()
	if err != nil {
		t.Fatalf("generateState: %v", err)
	}
	if s1 == "" || s2 == "" {
		t.Error("expected non-empty state strings")
	}
	if s1 == s2 {
		t.Error("expected unique states")
	}
}
