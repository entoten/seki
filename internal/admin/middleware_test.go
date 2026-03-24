package admin_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/entoten/seki/internal/admin"
	"github.com/entoten/seki/internal/storage"
	_ "github.com/entoten/seki/internal/storage/sqlite"
)

const testAPIKey = "test-secret-key-1234"

func newAuthMux(t *testing.T, apiKeys ...string) *http.ServeMux {
	t.Helper()
	s, err := storage.New(storage.TestDatabaseConfig())
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := s.Migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	handler := admin.NewHandler(s, apiKeys...)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	return mux
}

func TestMiddleware_ValidBearerKey(t *testing.T) {
	mux := newAuthMux(t, testAPIKey)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	req.Header.Set("Authorization", "Bearer "+testAPIKey)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code == http.StatusUnauthorized {
		t.Fatalf("expected request to pass auth, got 401: %s", rec.Body.String())
	}
}

func TestMiddleware_ValidXAPIKey(t *testing.T) {
	mux := newAuthMux(t, testAPIKey)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	req.Header.Set("X-API-Key", testAPIKey)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code == http.StatusUnauthorized {
		t.Fatalf("expected request to pass auth, got 401: %s", rec.Body.String())
	}
}

func TestMiddleware_MissingKey(t *testing.T) {
	mux := newAuthMux(t, testAPIKey)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}

	var problem admin.ProblemDetail
	if err := json.NewDecoder(rec.Body).Decode(&problem); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if problem.Detail != "missing API key" {
		t.Fatalf("expected 'missing API key', got %q", problem.Detail)
	}
}

func TestMiddleware_InvalidKey(t *testing.T) {
	mux := newAuthMux(t, testAPIKey)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	req.Header.Set("Authorization", "Bearer wrong-key")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}

	var problem admin.ProblemDetail
	if err := json.NewDecoder(rec.Body).Decode(&problem); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if problem.Detail != "invalid API key" {
		t.Fatalf("expected 'invalid API key', got %q", problem.Detail)
	}
}

func TestMiddleware_NoKeysConfigured(t *testing.T) {
	mux := newAuthMux(t) // no API keys = auth disabled

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code == http.StatusUnauthorized {
		t.Fatalf("expected request to pass when no keys configured, got 401")
	}
}

func TestMiddleware_MultipleKeysAccepted(t *testing.T) {
	key2 := "second-key-5678"
	mux := newAuthMux(t, testAPIKey, key2)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	req.Header.Set("Authorization", "Bearer "+key2)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code == http.StatusUnauthorized {
		t.Fatalf("expected second key to pass auth, got 401")
	}
}
