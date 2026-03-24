package admin_test

import (
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

func newAdminHandlerWithStore(t *testing.T, s storage.Storage) *admin.Handler {
	t.Helper()
	return admin.NewHandler(s)
}

func createTestUserAndSessions(t *testing.T, store storage.Storage, userID string, count int) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	err := store.CreateUser(context.Background(), &storage.User{
		ID:        userID,
		Email:     userID + "@example.com",
		CreatedAt: now,
		UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	for i := 0; i < count; i++ {
		sess := &storage.Session{
			ID:                userID + "-sess-" + string(rune('a'+i)),
			UserID:            userID,
			ClientID:          "client-1",
			IPAddress:         "1.2.3.4",
			UserAgent:         "TestAgent",
			CreatedAt:         now.Add(time.Duration(i) * time.Minute),
			ExpiresAt:         now.Add(time.Hour),
			LastActiveAt:      now,
			AbsoluteExpiresAt: now.Add(24 * time.Hour),
		}
		if err := store.CreateSession(context.Background(), sess); err != nil {
			t.Fatalf("create session %d: %v", i, err)
		}
	}
}

func TestListUserSessions(t *testing.T) {
	s, err := storage.New(storage.TestDatabaseConfig())
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := s.Migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	h := newAdminHandlerWithStore(t, s)
	mux := newMux(h)

	createTestUserAndSessions(t, s, "user-sess-1", 3)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/user-sess-1/sessions", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Sessions []storage.Session `json:"sessions"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Sessions) != 3 {
		t.Fatalf("expected 3 sessions, got %d", len(resp.Sessions))
	}
}

func TestListUserSessionsUserNotFound(t *testing.T) {
	s, err := storage.New(storage.TestDatabaseConfig())
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := s.Migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	h := newAdminHandlerWithStore(t, s)
	mux := newMux(h)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/nonexistent/sessions", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestRevokeUserSession(t *testing.T) {
	s, err := storage.New(storage.TestDatabaseConfig())
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := s.Migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	h := newAdminHandlerWithStore(t, s)
	mux := newMux(h)

	createTestUserAndSessions(t, s, "user-rev-1", 2)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/user-rev-1/sessions/user-rev-1-sess-a", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify only 1 session remains.
	sessions, err := s.ListSessionsByUserID(context.Background(), "user-rev-1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session remaining, got %d", len(sessions))
	}
}

func TestRevokeSessionNotFound(t *testing.T) {
	s, err := storage.New(storage.TestDatabaseConfig())
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := s.Migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	h := newAdminHandlerWithStore(t, s)
	mux := newMux(h)

	now := time.Now().UTC().Truncate(time.Second)
	_ = s.CreateUser(context.Background(), &storage.User{
		ID: "user-rev-2", Email: "rev2@example.com", CreatedAt: now, UpdatedAt: now,
	})

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/user-rev-2/sessions/nonexistent", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}
