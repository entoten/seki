package scim_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/Monet/seki/internal/scim"
	"github.com/Monet/seki/internal/storage"
	_ "github.com/Monet/seki/internal/storage/sqlite"
)

const testBaseURL = "http://localhost"

func setupHandler(t *testing.T) (*scim.Handler, *http.ServeMux) {
	t.Helper()
	s, err := storage.New(storage.TestDatabaseConfig())
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := s.Migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	h := scim.NewHandler(s, testBaseURL)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	return h, mux
}

func TestListUsersEmpty(t *testing.T) {
	_, mux := setupHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp scim.SCIMListResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.TotalResults != 0 {
		t.Fatalf("expected 0 total results, got %d", resp.TotalResults)
	}
	if resp.StartIndex != 1 {
		t.Fatalf("expected startIndex 1, got %d", resp.StartIndex)
	}
}

func TestCreateUser(t *testing.T) {
	_, mux := setupHandler(t)

	body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"alice@example.com","displayName":"Alice Smith","active":true}`
	req := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	ct := rec.Header().Get("Content-Type")
	if ct != "application/scim+json" {
		t.Fatalf("expected application/scim+json, got %s", ct)
	}

	var user scim.SCIMUser
	if err := json.NewDecoder(rec.Body).Decode(&user); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if user.ID == "" {
		t.Fatal("expected non-empty ID")
	}
	if user.UserName != "alice@example.com" {
		t.Fatalf("userName mismatch: %s", user.UserName)
	}
	if user.DisplayName != "Alice Smith" {
		t.Fatalf("displayName mismatch: %s", user.DisplayName)
	}
	if !user.Active {
		t.Fatal("expected active=true")
	}
	if user.Meta.ResourceType != "User" {
		t.Fatalf("meta.resourceType mismatch: %s", user.Meta.ResourceType)
	}
	if loc := rec.Header().Get("Location"); loc == "" {
		t.Fatal("expected Location header")
	}
}

func TestGetUser(t *testing.T) {
	_, mux := setupHandler(t)

	// Create user first.
	body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"bob@example.com","displayName":"Bob","active":true}`
	req := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d", rec.Code)
	}
	var created scim.SCIMUser
	_ = json.NewDecoder(rec.Body).Decode(&created)

	// Get user.
	req = httptest.NewRequest(http.MethodGet, "/scim/v2/Users/"+created.ID, nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var got scim.SCIMUser
	_ = json.NewDecoder(rec.Body).Decode(&got)
	if got.ID != created.ID {
		t.Fatalf("ID mismatch: %s vs %s", got.ID, created.ID)
	}
	if got.UserName != "bob@example.com" {
		t.Fatalf("userName mismatch: %s", got.UserName)
	}
}

func TestGetUserNotFound(t *testing.T) {
	_, mux := setupHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users/nonexistent", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestPatchUser(t *testing.T) {
	_, mux := setupHandler(t)

	// Create user.
	body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"patch@example.com","displayName":"Original","active":true}`
	req := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d", rec.Code)
	}
	var created scim.SCIMUser
	_ = json.NewDecoder(rec.Body).Decode(&created)

	// Patch: update displayName.
	patchBody := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"Updated"}]}`
	req = httptest.NewRequest(http.MethodPatch, "/scim/v2/Users/"+created.ID, bytes.NewBufferString(patchBody))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var patched scim.SCIMUser
	_ = json.NewDecoder(rec.Body).Decode(&patched)
	if patched.DisplayName != "Updated" {
		t.Fatalf("displayName not updated: %s", patched.DisplayName)
	}
	if patched.UserName != "patch@example.com" {
		t.Fatalf("userName should be unchanged: %s", patched.UserName)
	}
}

func TestPatchUserDeactivate(t *testing.T) {
	_, mux := setupHandler(t)

	body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"deact@example.com","displayName":"Active User","active":true}`
	req := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d", rec.Code)
	}
	var created scim.SCIMUser
	_ = json.NewDecoder(rec.Body).Decode(&created)

	// Deactivate via PATCH.
	patchBody := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false}]}`
	req = httptest.NewRequest(http.MethodPatch, "/scim/v2/Users/"+created.ID, bytes.NewBufferString(patchBody))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var patched scim.SCIMUser
	_ = json.NewDecoder(rec.Body).Decode(&patched)
	if patched.Active {
		t.Fatal("expected active=false after deactivation")
	}
}

func TestDeleteUser(t *testing.T) {
	_, mux := setupHandler(t)

	// Create user.
	body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"del@example.com","displayName":"Delete Me","active":true}`
	req := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d", rec.Code)
	}
	var created scim.SCIMUser
	_ = json.NewDecoder(rec.Body).Decode(&created)

	// Delete (soft).
	req = httptest.NewRequest(http.MethodDelete, "/scim/v2/Users/"+created.ID, nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rec.Code)
	}

	// Verify user still exists but is deactivated.
	req = httptest.NewRequest(http.MethodGet, "/scim/v2/Users/"+created.ID, nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var got scim.SCIMUser
	_ = json.NewDecoder(rec.Body).Decode(&got)
	if got.Active {
		t.Fatal("expected user to be deactivated after DELETE")
	}
}

func TestListGroups(t *testing.T) {
	_, mux := setupHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/scim/v2/Groups", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp scim.SCIMListResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if resp.TotalResults != 0 {
		t.Fatalf("expected 0 total results, got %d", resp.TotalResults)
	}
}

func TestCreateAndGetGroup(t *testing.T) {
	_, mux := setupHandler(t)

	body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Engineering"}`
	req := httptest.NewRequest(http.MethodPost, "/scim/v2/Groups", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var created scim.SCIMGroup
	_ = json.NewDecoder(rec.Body).Decode(&created)
	if created.DisplayName != "Engineering" {
		t.Fatalf("displayName mismatch: %s", created.DisplayName)
	}

	// Get the group.
	req = httptest.NewRequest(http.MethodGet, "/scim/v2/Groups/"+created.ID, nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var got scim.SCIMGroup
	_ = json.NewDecoder(rec.Body).Decode(&got)
	if got.DisplayName != "Engineering" {
		t.Fatalf("displayName mismatch: %s", got.DisplayName)
	}
}

func TestServiceProviderConfig(t *testing.T) {
	_, mux := setupHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/scim/v2/ServiceProviderConfig", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	ct := rec.Header().Get("Content-Type")
	if ct != "application/scim+json" {
		t.Fatalf("expected application/scim+json, got %s", ct)
	}

	var config map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&config); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Verify patch is supported.
	patch, ok := config["patch"].(map[string]any)
	if !ok {
		t.Fatal("missing patch config")
	}
	if supported, ok := patch["supported"].(bool); !ok || !supported {
		t.Fatal("patch should be supported")
	}

	// Verify filter is supported.
	filter, ok := config["filter"].(map[string]any)
	if !ok {
		t.Fatal("missing filter config")
	}
	if supported, ok := filter["supported"].(bool); !ok || !supported {
		t.Fatal("filter should be supported")
	}
}

func TestFilterByUserName(t *testing.T) {
	_, mux := setupHandler(t)

	// Create two users.
	for _, email := range []string{"filter1@example.com", "filter2@example.com"} {
		body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"` + email + `","displayName":"Test","active":true}`
		req := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", bytes.NewBufferString(body))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("create: expected 201, got %d", rec.Code)
		}
	}

	// Filter by userName eq.
	filterURL := "/scim/v2/Users?filter=" + url.QueryEscape(`userName eq "filter1@example.com"`)
	req := httptest.NewRequest(http.MethodGet, filterURL, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp scim.SCIMListResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if resp.TotalResults != 1 {
		t.Fatalf("expected 1 result, got %d", resp.TotalResults)
	}

	// Decode the Resources to check the email.
	resources, err := json.Marshal(resp.Resources)
	if err != nil {
		t.Fatalf("marshal resources: %v", err)
	}
	var users []scim.SCIMUser
	if err := json.Unmarshal(resources, &users); err != nil {
		t.Fatalf("unmarshal users: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(users))
	}
	if users[0].UserName != "filter1@example.com" {
		t.Fatalf("userName mismatch: %s", users[0].UserName)
	}
}

func TestFilterByUserNameNotFound(t *testing.T) {
	_, mux := setupHandler(t)

	filterURL := "/scim/v2/Users?filter=" + url.QueryEscape(`userName eq "nobody@example.com"`)
	req := httptest.NewRequest(http.MethodGet, filterURL, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp scim.SCIMListResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if resp.TotalResults != 0 {
		t.Fatalf("expected 0 results, got %d", resp.TotalResults)
	}
}

func TestSchemas(t *testing.T) {
	_, mux := setupHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/scim/v2/Schemas", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp scim.SCIMListResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if resp.TotalResults != 2 {
		t.Fatalf("expected 2 schemas, got %d", resp.TotalResults)
	}
}

func TestResourceTypes(t *testing.T) {
	_, mux := setupHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/scim/v2/ResourceTypes", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp scim.SCIMListResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if resp.TotalResults != 2 {
		t.Fatalf("expected 2 resource types, got %d", resp.TotalResults)
	}
}

func TestDeleteGroup(t *testing.T) {
	_, mux := setupHandler(t)

	// Create group.
	body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"To Delete"}`
	req := httptest.NewRequest(http.MethodPost, "/scim/v2/Groups", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var created scim.SCIMGroup
	_ = json.NewDecoder(rec.Body).Decode(&created)

	// Delete.
	req = httptest.NewRequest(http.MethodDelete, "/scim/v2/Groups/"+created.ID, nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rec.Code)
	}

	// Verify it's gone.
	req = httptest.NewRequest(http.MethodGet, "/scim/v2/Groups/"+created.ID, nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 after delete, got %d", rec.Code)
	}
}
