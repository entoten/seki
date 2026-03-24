package admin_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/entoten/seki/internal/admin"
	"github.com/entoten/seki/internal/storage"

	_ "github.com/entoten/seki/internal/storage/sqlite"
)

func setupPATHandler(t *testing.T) (*admin.Handler, storage.Storage) {
	t.Helper()
	s, err := storage.New(storage.TestDatabaseConfig())
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := s.Migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	// Create test user.
	now := time.Now().UTC().Truncate(time.Second)
	err = s.CreateUser(context.Background(), &storage.User{
		ID:        "user-pat",
		Email:     "pat@example.com",
		CreatedAt: now,
		UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	return admin.NewHandler(s), s
}

func newPATMux(h *admin.Handler) *http.ServeMux {
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	return mux
}

func TestCreatePAT(t *testing.T) {
	h, _ := setupPATHandler(t)
	mux := newPATMux(h)

	body := `{"name":"ci-token","scopes":["read","write"],"expires_in":3600}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/user-pat/tokens", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Token string                       `json:"token"`
		PAT   *storage.PersonalAccessToken `json:"pat"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if resp.Token == "" {
		t.Fatal("expected non-empty token")
	}
	if resp.PAT == nil {
		t.Fatal("expected non-nil PAT")
	}
	if resp.PAT.Name != "ci-token" {
		t.Fatalf("expected ci-token, got %s", resp.PAT.Name)
	}
}

func TestCreatePATMissingName(t *testing.T) {
	h, _ := setupPATHandler(t)
	mux := newPATMux(h)

	body := `{"scopes":["read"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/user-pat/tokens", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestCreatePATUserNotFound(t *testing.T) {
	h, _ := setupPATHandler(t)
	mux := newPATMux(h)

	body := `{"name":"test"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/nonexistent/tokens", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestListPATs(t *testing.T) {
	h, _ := setupPATHandler(t)
	mux := newPATMux(h)

	// Create two tokens.
	for _, name := range []string{"token-a", "token-b"} {
		body := `{"name":"` + name + `"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/users/user-pat/tokens", bytes.NewBufferString(body))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("create %s: expected 201, got %d", name, rec.Code)
		}
	}

	// List.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/user-pat/tokens", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Tokens []*storage.PersonalAccessToken `json:"tokens"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Tokens) != 2 {
		t.Fatalf("expected 2 tokens, got %d", len(resp.Tokens))
	}

	// Verify token hash is not exposed (it's tagged with json:"-").
	raw := rec.Body.String()
	if bytes.Contains([]byte(raw), []byte("token_hash")) {
		t.Fatal("token_hash should not be in response (json:\"-\" tag)")
	}
}

func TestDeletePAT(t *testing.T) {
	h, _ := setupPATHandler(t)
	mux := newPATMux(h)

	// Create a token.
	body := `{"name":"to-delete"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/user-pat/tokens", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var createResp struct {
		PAT *storage.PersonalAccessToken `json:"pat"`
	}
	_ = json.NewDecoder(rec.Body).Decode(&createResp)
	tokenID := createResp.PAT.ID

	// Delete.
	req = httptest.NewRequest(http.MethodDelete, "/api/v1/users/user-pat/tokens/"+tokenID, nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify it's gone.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/users/user-pat/tokens", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var listResp struct {
		Tokens []*storage.PersonalAccessToken `json:"tokens"`
	}
	_ = json.NewDecoder(rec.Body).Decode(&listResp)
	if len(listResp.Tokens) != 0 {
		t.Fatalf("expected 0 tokens after delete, got %d", len(listResp.Tokens))
	}
}

func TestDeletePATNotFound(t *testing.T) {
	h, _ := setupPATHandler(t)
	mux := newPATMux(h)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/user-pat/tokens/nonexistent", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}
