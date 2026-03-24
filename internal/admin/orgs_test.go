package admin_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/entoten/seki/internal/storage"
)

// ---------------------------------------------------------------------------
// Org CRUD via API
// ---------------------------------------------------------------------------

func TestOrgCRUDViaAPI(t *testing.T) {
	h := setupHandler(t)
	mux := newMux(h)

	// Create org
	body := `{"slug":"acme","name":"Acme Corp","domains":["acme.com"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/orgs", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create org: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var org map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&org)
	if org["slug"] != "acme" {
		t.Fatalf("slug mismatch: %v", org["slug"])
	}

	// Get org by slug
	req = httptest.NewRequest(http.MethodGet, "/api/v1/orgs/acme", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get org: expected 200, got %d", rec.Code)
	}

	// Update org
	body = `{"name":"Acme Corporation"}`
	req = httptest.NewRequest(http.MethodPatch, "/api/v1/orgs/acme", bytes.NewBufferString(body))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("update org: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var updated map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&updated)
	if updated["name"] != "Acme Corporation" {
		t.Fatalf("name not updated: %v", updated["name"])
	}

	// List orgs
	req = httptest.NewRequest(http.MethodGet, "/api/v1/orgs", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list orgs: expected 200, got %d", rec.Code)
	}
	var listResp map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&listResp)
	data := listResp["data"].([]any)
	if len(data) != 1 {
		t.Fatalf("expected 1 org, got %d", len(data))
	}

	// Get non-existent org
	req = httptest.NewRequest(http.MethodGet, "/api/v1/orgs/nonexistent", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}

	// Delete org
	req = httptest.NewRequest(http.MethodDelete, "/api/v1/orgs/acme", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete org: expected 204, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify deleted
	req = httptest.NewRequest(http.MethodGet, "/api/v1/orgs/acme", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 after delete, got %d", rec.Code)
	}
}

func TestDuplicateSlugReturns409(t *testing.T) {
	h := setupHandler(t)
	mux := newMux(h)

	body := `{"slug":"dupe","name":"Org"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/orgs", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("first create: expected 201, got %d", rec.Code)
	}

	body = `{"id":"org_dupe2","slug":"dupe","name":"Org 2"}`
	req = httptest.NewRequest(http.MethodPost, "/api/v1/orgs", bytes.NewBufferString(body))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate slug: expected 409, got %d: %s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Member add/remove/list
// ---------------------------------------------------------------------------

func TestMemberViaAPI(t *testing.T) {
	h := setupHandler(t)
	mux := newMux(h)

	// Create org
	body := `{"slug":"members-org","name":"Members Org"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/orgs", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create org: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	// Create a user via the users API.
	userBody := `{"email":"membertest@example.com","display_name":"MemberTest"}`
	req = httptest.NewRequest(http.MethodPost, "/api/v1/users", bytes.NewBufferString(userBody))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create user: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var createdUser storage.User
	_ = json.NewDecoder(rec.Body).Decode(&createdUser)

	// Add member
	body = `{"user_id":"` + createdUser.ID + `","role":"admin"}`
	req = httptest.NewRequest(http.MethodPost, "/api/v1/orgs/members-org/members", bytes.NewBufferString(body))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("add member: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	// List members
	req = httptest.NewRequest(http.MethodGet, "/api/v1/orgs/members-org/members", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list members: expected 200, got %d", rec.Code)
	}
	var resp map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	members := resp["data"].([]any)
	if len(members) != 1 {
		t.Fatalf("expected 1 member, got %d", len(members))
	}

	// Update member role
	body = `{"role":"viewer"}`
	req = httptest.NewRequest(http.MethodPatch, "/api/v1/orgs/members-org/members/"+createdUser.ID, bytes.NewBufferString(body))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("update member role: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var memberResp map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&memberResp)
	if memberResp["role"] != "viewer" {
		t.Fatalf("role not updated: %v", memberResp["role"])
	}

	// Remove member
	req = httptest.NewRequest(http.MethodDelete, "/api/v1/orgs/members-org/members/"+createdUser.ID, nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("remove member: expected 204, got %d", rec.Code)
	}

	// Verify removed
	req = httptest.NewRequest(http.MethodGet, "/api/v1/orgs/members-org/members", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	members = resp["data"].([]any)
	if len(members) != 0 {
		t.Fatalf("expected 0 members after remove, got %d", len(members))
	}
}

// ---------------------------------------------------------------------------
// Role CRUD via API
// ---------------------------------------------------------------------------

func TestRoleCRUDViaAPI(t *testing.T) {
	h := setupHandler(t)
	mux := newMux(h)

	// Create org
	body := `{"slug":"roles-org","name":"Roles Org"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/orgs", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create org: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	// Create role
	body = `{"name":"editor","permissions":["read","write"]}`
	req = httptest.NewRequest(http.MethodPost, "/api/v1/orgs/roles-org/roles", bytes.NewBufferString(body))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create role: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	// List roles
	req = httptest.NewRequest(http.MethodGet, "/api/v1/orgs/roles-org/roles", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list roles: expected 200, got %d", rec.Code)
	}
	var resp map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	roles := resp["data"].([]any)
	if len(roles) != 1 {
		t.Fatalf("expected 1 role, got %d", len(roles))
	}

	// Update role permissions
	body = `{"permissions":["read"]}`
	req = httptest.NewRequest(http.MethodPatch, "/api/v1/orgs/roles-org/roles/editor", bytes.NewBufferString(body))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("update role: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var roleResp map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&roleResp)
	perms := roleResp["permissions"].([]any)
	if len(perms) != 1 || perms[0] != "read" {
		t.Fatalf("permissions not updated: %v", perms)
	}

	// Delete role
	req = httptest.NewRequest(http.MethodDelete, "/api/v1/orgs/roles-org/roles/editor", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete role: expected 204, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify deleted
	req = httptest.NewRequest(http.MethodGet, "/api/v1/orgs/roles-org/roles", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	roles = resp["data"].([]any)
	if len(roles) != 0 {
		t.Fatalf("expected 0 roles after delete, got %d", len(roles))
	}
}
