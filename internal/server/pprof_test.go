package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/entoten/seki/internal/config"
	"github.com/entoten/seki/internal/crypto"
	"github.com/entoten/seki/internal/storage"
	_ "github.com/entoten/seki/internal/storage/sqlite"
)

func TestPprof_Enabled_Returns200(t *testing.T) {
	store, err := storage.New(storage.TestDatabaseConfig())
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	if err := store.Migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer := crypto.NewEd25519SignerFromKey(priv, "test-key", "https://test.example.com", time.Hour)

	cfg := &config.Config{
		Server: config.ServerConfig{
			Address: ":0",
			Issuer:  "https://test.example.com",
		},
		Debug: config.DebugConfig{
			PprofEnabled: true,
		},
		// No API keys configured, so auth is skipped.
		Admin: config.AdminConfig{},
		CORS: config.CORSConfig{
			AllowedOrigins: []string{"*"},
		},
	}

	s := New(cfg, store, signer)

	req := httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for pprof index, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestPprof_Disabled_Returns404(t *testing.T) {
	s := newTestServer(t) // default config has pprof disabled

	req := httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)

	// When pprof is disabled, the route should not be registered.
	// Go's default mux returns 404 for unregistered routes.
	if rec.Code == http.StatusOK {
		t.Fatalf("expected non-200 for disabled pprof, got %d", rec.Code)
	}
}

func TestPprof_Enabled_WithAPIKey_RequiresAuth(t *testing.T) {
	store, err := storage.New(storage.TestDatabaseConfig())
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	if err := store.Migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer := crypto.NewEd25519SignerFromKey(priv, "test-key", "https://test.example.com", time.Hour)

	cfg := &config.Config{
		Server: config.ServerConfig{
			Address: ":0",
			Issuer:  "https://test.example.com",
		},
		Debug: config.DebugConfig{
			PprofEnabled: true,
		},
		Admin: config.AdminConfig{
			APIKeys: []string{"super-secret-key"},
		},
		CORS: config.CORSConfig{
			AllowedOrigins: []string{"*"},
		},
	}

	s := New(cfg, store, signer)

	// Request without API key should be rejected.
	req := httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without API key, got %d", rec.Code)
	}

	// Request with correct API key should succeed.
	req2 := httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil)
	req2.Header.Set("X-API-Key", "super-secret-key")
	rec2 := httptest.NewRecorder()
	s.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200 with API key, got %d: %s", rec2.Code, rec2.Body.String())
	}
}
