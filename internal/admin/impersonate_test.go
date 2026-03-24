package admin_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Monet/seki/internal/admin"
	"github.com/Monet/seki/internal/audit"
	"github.com/Monet/seki/internal/config"
	"github.com/Monet/seki/internal/storage"
	_ "github.com/Monet/seki/internal/storage/sqlite"
)

func setupImpersonateHandler(t *testing.T) (*admin.Handler, storage.Storage) {
	t.Helper()
	s, err := storage.New(storage.TestDatabaseConfig())
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := s.Migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	h := admin.NewHandler(s)
	logger := audit.NewLogger(s, config.AuditConfig{})
	h.SetAuditLogger(logger)
	return h, s
}

func createTestUser(t *testing.T, s storage.Storage, userID string) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	err := s.CreateUser(context.Background(), &storage.User{
		ID:        userID,
		Email:     userID + "@example.com",
		CreatedAt: now,
		UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
}

func TestImpersonateCreatesSession(t *testing.T) {
	h, s := setupImpersonateHandler(t)
	mux := newMux(h)

	createTestUser(t, s, "imp-user-1")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/imp-user-1/impersonate", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		SessionID   string `json:"session_id"`
		CookieValue string `json:"cookie_value"`
		ExpiresAt   string `json:"expires_at"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.SessionID == "" {
		t.Fatal("expected non-empty session_id")
	}
	if resp.CookieValue == "" {
		t.Fatal("expected non-empty cookie_value")
	}
	if resp.SessionID != resp.CookieValue {
		t.Fatalf("session_id and cookie_value should match: %s != %s", resp.SessionID, resp.CookieValue)
	}

	// Verify the session was actually created in the store.
	sess, err := s.GetSession(context.Background(), resp.SessionID)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	if sess.UserID != "imp-user-1" {
		t.Fatalf("session user_id mismatch: got %s", sess.UserID)
	}
}

func TestImpersonateSessionHasMetadata(t *testing.T) {
	h, s := setupImpersonateHandler(t)
	mux := newMux(h)

	createTestUser(t, s, "imp-user-2")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/imp-user-2/impersonate", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		SessionID string `json:"session_id"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	sess, err := s.GetSession(context.Background(), resp.SessionID)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}

	var meta map[string]interface{}
	if err := json.Unmarshal(sess.Metadata, &meta); err != nil {
		t.Fatalf("unmarshal metadata: %v", err)
	}
	if impersonated, ok := meta["impersonated"].(bool); !ok || !impersonated {
		t.Fatalf("expected impersonated=true in metadata, got %v", meta)
	}
	if _, ok := meta["impersonator_id"]; !ok {
		t.Fatal("expected impersonator_id in metadata")
	}
}

func TestImpersonateNonExistentUserReturns404(t *testing.T) {
	h, _ := setupImpersonateHandler(t)
	mux := newMux(h)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/nonexistent/impersonate", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestImpersonateAuditLog(t *testing.T) {
	h, s := setupImpersonateHandler(t)
	mux := newMux(h)

	createTestUser(t, s, "imp-user-3")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/imp-user-3/impersonate", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	// Check audit logs for the impersonation event.
	logs, _, err := s.ListAuditLogs(context.Background(), storage.AuditListOptions{
		Action: "user.impersonated",
		Limit:  10,
	})
	if err != nil {
		t.Fatalf("list audit logs: %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("expected 1 audit log entry, got %d", len(logs))
	}

	entry := logs[0]
	if entry.ActorID != "admin" {
		t.Fatalf("expected actor_id=admin, got %s", entry.ActorID)
	}
	if entry.Resource != "user" {
		t.Fatalf("expected resource=user, got %s", entry.Resource)
	}
	if entry.ResourceID != "imp-user-3" {
		t.Fatalf("expected resource_id=imp-user-3, got %s", entry.ResourceID)
	}

	var meta map[string]interface{}
	if err := json.Unmarshal(entry.Metadata, &meta); err != nil {
		t.Fatalf("unmarshal audit metadata: %v", err)
	}
	if _, ok := meta["impersonator_id"]; !ok {
		t.Fatal("expected impersonator_id in audit metadata")
	}
	if _, ok := meta["session_id"]; !ok {
		t.Fatal("expected session_id in audit metadata")
	}
}
