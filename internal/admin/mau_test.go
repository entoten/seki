package admin_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Monet/seki/internal/admin"
	"github.com/Monet/seki/internal/storage"
	_ "github.com/Monet/seki/internal/storage/sqlite"
)

func setupMAUHandler(t *testing.T) (*admin.Handler, storage.Storage) {
	t.Helper()
	s, err := storage.New(storage.TestDatabaseConfig())
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := s.Migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return admin.NewHandler(s), s
}

func createAuditLogin(t *testing.T, store storage.Storage, actorID string, createdAt time.Time) {
	t.Helper()
	entry := &storage.AuditEntry{
		ID:        fmt.Sprintf("audit-%s-%d", actorID, createdAt.UnixNano()),
		ActorID:   actorID,
		Action:    "user.login",
		Resource:  "session",
		CreatedAt: createdAt,
		Metadata:  json.RawMessage(`{}`),
	}
	if err := store.CreateAuditLog(context.Background(), entry); err != nil {
		t.Fatalf("create audit log: %v", err)
	}
}

func TestMAUEndpoint(t *testing.T) {
	h, store := setupMAUHandler(t)
	mux := newMux(h)

	now := time.Now().UTC()

	// Create users
	for _, uid := range []string{"mau-user-1", "mau-user-2", "mau-user-3"} {
		err := store.CreateUser(context.Background(), &storage.User{
			ID:        uid,
			Email:     uid + "@example.com",
			CreatedAt: now,
			UpdatedAt: now,
			Metadata:  json.RawMessage(`{}`),
		})
		if err != nil {
			t.Fatalf("create user: %v", err)
		}
	}

	// Create login audit entries this month
	createAuditLogin(t, store, "mau-user-1", now)
	createAuditLogin(t, store, "mau-user-2", now)
	createAuditLogin(t, store, "mau-user-1", now.Add(-time.Hour)) // duplicate user
	createAuditLogin(t, store, "mau-user-3", now)

	// Get MAU
	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/mau", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get mau: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	mau := int(resp["mau"].(float64))
	if mau != 3 {
		t.Fatalf("expected MAU 3, got %d", mau)
	}
}

func TestMAUByOrg(t *testing.T) {
	h, store := setupMAUHandler(t)
	mux := newMux(h)

	ctx := context.Background()
	now := time.Now().UTC()

	// Create org
	body := `{"slug":"mau-org","name":"MAU Org"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/orgs", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create org: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var org storage.Organization
	_ = json.NewDecoder(rec.Body).Decode(&org)

	// Create users and add one as member
	for _, uid := range []string{"mau-org-user-1", "mau-org-user-2"} {
		err := store.CreateUser(ctx, &storage.User{
			ID:        uid,
			Email:     uid + "@example.com",
			CreatedAt: now,
			UpdatedAt: now,
			Metadata:  json.RawMessage(`{}`),
		})
		if err != nil {
			t.Fatalf("create user: %v", err)
		}
	}

	// Only user-1 is a member
	err := store.AddMember(ctx, &storage.OrgMember{
		OrgID:    org.ID,
		UserID:   "mau-org-user-1",
		Role:     "member",
		JoinedAt: now,
	})
	if err != nil {
		t.Fatalf("add member: %v", err)
	}

	// Both users log in
	createAuditLogin(t, store, "mau-org-user-1", now)
	createAuditLogin(t, store, "mau-org-user-2", now)

	// Get org-specific MAU
	req = httptest.NewRequest(http.MethodGet, "/api/v1/metrics/mau?org=mau-org", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get mau by org: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	mau := int(resp["mau"].(float64))
	if mau != 1 {
		t.Fatalf("expected org MAU 1, got %d", mau)
	}
}

func TestMAUHistory(t *testing.T) {
	h, store := setupMAUHandler(t)
	mux := newMux(h)

	now := time.Now().UTC()

	// Create user and login
	err := store.CreateUser(context.Background(), &storage.User{
		ID:        "mau-hist-user",
		Email:     "hist@example.com",
		CreatedAt: now,
		UpdatedAt: now,
		Metadata:  json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	createAuditLogin(t, store, "mau-hist-user", now)

	// Get history
	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/mau/history?months=3", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get mau history: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	data := resp["data"].([]interface{})
	if len(data) != 3 {
		t.Fatalf("expected 3 months, got %d", len(data))
	}

	// First entry (current month) should have MAU >= 1
	first := data[0].(map[string]interface{})
	mau := int(first["mau"].(float64))
	if mau < 1 {
		t.Fatalf("expected current month MAU >= 1, got %d", mau)
	}
}

func TestMAUZeroForEmptyMonth(t *testing.T) {
	h, _ := setupMAUHandler(t)
	mux := newMux(h)

	// No login data at all — MAU should be 0
	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/mau", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp map[string]interface{}
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	mau := int(resp["mau"].(float64))
	if mau != 0 {
		t.Fatalf("expected 0 MAU for empty month, got %d", mau)
	}
}
