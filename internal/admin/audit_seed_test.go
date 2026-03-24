package admin_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Monet/seki/internal/admin"
	"github.com/Monet/seki/internal/config"
	"github.com/Monet/seki/internal/storage"
)

func TestAuditLogsViaAPI(t *testing.T) {
	h := setupHandler(t)
	mux := newMux(h)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit-logs", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	data, ok := resp["data"].([]interface{})
	if !ok {
		t.Fatal("expected data array")
	}
	if len(data) != 0 {
		t.Fatalf("expected 0 audit logs, got %d", len(data))
	}
}

func TestAuditLogsWithLimitParam(t *testing.T) {
	h := setupHandler(t)
	mux := newMux(h)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit-logs?limit=10&actor_id=usr1&action=login", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestSeedOrgsFromConfig(t *testing.T) {
	s, err := storage.New(storage.TestDatabaseConfig())
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := s.Migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	ctx := context.Background()
	orgs := []config.OrganizationConfig{
		{
			Slug:    "acme",
			Name:    "Acme Corp",
			Domains: []string{"acme.com"},
			Roles: []config.RoleConfig{
				{Name: "admin", Permissions: []string{"read", "write", "delete"}},
				{Name: "viewer", Permissions: []string{"read"}},
			},
		},
		{
			Slug: "beta",
			Name: "Beta Inc",
		},
	}

	if err := admin.SeedOrgsFromConfig(ctx, s, orgs); err != nil {
		t.Fatalf("SeedOrgsFromConfig: %v", err)
	}

	// Verify orgs created.
	org, err := s.GetOrgBySlug(ctx, "acme")
	if err != nil {
		t.Fatalf("GetOrgBySlug(acme): %v", err)
	}
	if org.Name != "Acme Corp" {
		t.Errorf("name = %q, want Acme Corp", org.Name)
	}

	// Verify roles created.
	roles, err := s.ListRoles(ctx, org.ID)
	if err != nil {
		t.Fatalf("ListRoles: %v", err)
	}
	if len(roles) != 2 {
		t.Fatalf("expected 2 roles, got %d", len(roles))
	}

	// Verify idempotent.
	if err := admin.SeedOrgsFromConfig(ctx, s, orgs); err != nil {
		t.Fatalf("second SeedOrgsFromConfig: %v", err)
	}

	// Seed with nil.
	if err := admin.SeedOrgsFromConfig(ctx, s, nil); err != nil {
		t.Fatalf("SeedOrgsFromConfig nil: %v", err)
	}
}

func TestSessionsViaAPI(t *testing.T) {
	s, err := storage.New(storage.TestDatabaseConfig())
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := s.Migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	h := admin.NewHandler(s)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	// Create a user.
	body := `{"email":"sessions@example.com","display_name":"Sessions"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create user: expected 201, got %d", rec.Code)
	}
	var created storage.User
	json.NewDecoder(rec.Body).Decode(&created)

	// Create a session for that user.
	now := time.Now().UTC().Truncate(time.Second)
	sess := &storage.Session{
		ID:                "ses_api_test",
		UserID:            created.ID,
		IPAddress:         "127.0.0.1",
		UserAgent:         "TestAgent",
		Metadata:          json.RawMessage(`{}`),
		CreatedAt:         now,
		ExpiresAt:         now.Add(1 * time.Hour),
		LastActiveAt:      now,
		AbsoluteExpiresAt: now.Add(24 * time.Hour),
	}
	if err := s.CreateSession(context.Background(), sess); err != nil {
		t.Fatalf("create session: %v", err)
	}

	// List sessions.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/users/"+created.ID+"/sessions", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list sessions: expected 200, got %d", rec.Code)
	}

	// Revoke session.
	req = httptest.NewRequest(http.MethodDelete, "/api/v1/users/"+created.ID+"/sessions/ses_api_test", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("revoke: expected 204, got %d: %s", rec.Code, rec.Body.String())
	}

	// Revoke non-existent session.
	req = httptest.NewRequest(http.MethodDelete, "/api/v1/users/"+created.ID+"/sessions/nonexistent", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("revoke nonexistent: expected 404, got %d", rec.Code)
	}

	// Revoke session belonging to different user.
	req = httptest.NewRequest(http.MethodDelete, "/api/v1/users/nonexistent/sessions/ses_api_test", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("revoke wrong user: expected 404, got %d", rec.Code)
	}

	// List sessions for non-existent user.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/users/nonexistent/sessions", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestAPIKeyMiddleware(t *testing.T) {
	s, err := storage.New(storage.TestDatabaseConfig())
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := s.Migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	// Create handler with API key requirement.
	h := admin.NewHandler(s, "secret-api-key")
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	// Without key: should fail.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no key: expected 401, got %d", rec.Code)
	}

	// With wrong key.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	req.Header.Set("Authorization", "Bearer wrong-key")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong key: expected 401, got %d", rec.Code)
	}

	// With correct key via Bearer.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	req.Header.Set("Authorization", "Bearer secret-api-key")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("correct key: expected 200, got %d", rec.Code)
	}

	// With correct key via X-API-Key.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	req.Header.Set("X-API-Key", "secret-api-key")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("X-API-Key: expected 200, got %d", rec.Code)
	}
}

func TestCreateUserInvalidBody(t *testing.T) {
	h := setupHandler(t)
	mux := newMux(h)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/users", bytes.NewBufferString("not json"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestCreateUserInvalidEmail(t *testing.T) {
	h := setupHandler(t)
	mux := newMux(h)

	body := `{"email":"not-valid","display_name":"Test"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestUpdateUserNotFound(t *testing.T) {
	h := setupHandler(t)
	mux := newMux(h)

	body := `{"display_name":"Updated"}`
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/users/nonexistent", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestDeleteOrgNotFound(t *testing.T) {
	h := setupHandler(t)
	mux := newMux(h)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/orgs/nonexistent", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestRemoveMemberNotFound(t *testing.T) {
	h := setupHandler(t)
	mux := newMux(h)

	// Create org first.
	body := `{"slug":"rm-org","name":"RM Org"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/orgs", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create org: expected 201, got %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodDelete, "/api/v1/orgs/rm-org/members/nobody", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestDeleteClientNotFound(t *testing.T) {
	h := setupHandler(t)
	mux := newMux(h)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/clients/nonexistent", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestAddMemberMissingUserID(t *testing.T) {
	h := setupHandler(t)
	mux := newMux(h)

	// Create org first.
	body := `{"slug":"member-test-org","name":"Member Org"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/orgs", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create org: expected 201, got %d", rec.Code)
	}

	body = `{"role":"admin"}`
	req = httptest.NewRequest(http.MethodPost, "/api/v1/orgs/member-test-org/members", bytes.NewBufferString(body))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestUpdateMemberRoleMissing(t *testing.T) {
	h := setupHandler(t)
	mux := newMux(h)

	body := `{"slug":"role-test-org","name":"Role Org"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/orgs", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create org: expected 201, got %d", rec.Code)
	}

	body = `{"role":""}`
	req = httptest.NewRequest(http.MethodPatch, "/api/v1/orgs/role-test-org/members/someuser", bytes.NewBufferString(body))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestRoleNotFoundErrors(t *testing.T) {
	h := setupHandler(t)
	mux := newMux(h)

	body := `{"slug":"role-nf-org","name":"Role NF Org"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/orgs", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create org: expected 201, got %d", rec.Code)
	}

	// Update non-existent role.
	body = `{"permissions":["read"]}`
	req = httptest.NewRequest(http.MethodPatch, "/api/v1/orgs/role-nf-org/roles/nonexistent", bytes.NewBufferString(body))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("update role: expected 404, got %d", rec.Code)
	}

	// Delete non-existent role.
	req = httptest.NewRequest(http.MethodDelete, "/api/v1/orgs/role-nf-org/roles/nonexistent", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("delete role: expected 404, got %d", rec.Code)
	}
}
