package scim_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Monet/seki/internal/scim"
	"github.com/Monet/seki/internal/storage"
	_ "github.com/Monet/seki/internal/storage/sqlite"
)

func TestPatchGroupRenameAndMembers(t *testing.T) {
	_, mux := setupHandler(t)

	// Create a user first (needed for member add).
	userBody := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"member@example.com","displayName":"Member","active":true}`
	req := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", bytes.NewBufferString(userBody))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create user: expected 201, got %d", rec.Code)
	}
	var user scim.SCIMUser
	json.NewDecoder(rec.Body).Decode(&user)

	// Create group.
	body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Original Name"}`
	req = httptest.NewRequest(http.MethodPost, "/scim/v2/Groups", bytes.NewBufferString(body))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create group: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var created scim.SCIMGroup
	json.NewDecoder(rec.Body).Decode(&created)

	// Patch: rename group.
	patchBody := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"New Name"}]}`
	req = httptest.NewRequest(http.MethodPatch, "/scim/v2/Groups/"+created.ID, bytes.NewBufferString(patchBody))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch rename: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var patched scim.SCIMGroup
	json.NewDecoder(rec.Body).Decode(&patched)
	if patched.DisplayName != "New Name" {
		t.Errorf("displayName = %q, want New Name", patched.DisplayName)
	}

	// Patch: add member.
	addMemberBody := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"add","path":"members","value":[{"value":"` + user.ID + `"}]}]}`
	req = httptest.NewRequest(http.MethodPatch, "/scim/v2/Groups/"+created.ID, bytes.NewBufferString(addMemberBody))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch add member: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var withMember scim.SCIMGroup
	json.NewDecoder(rec.Body).Decode(&withMember)
	if len(withMember.Members) != 1 {
		t.Fatalf("expected 1 member, got %d", len(withMember.Members))
	}

	// Patch: remove member.
	removeMemberBody := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"remove","path":"members[value eq \"` + user.ID + `\"]"}]}`
	req = httptest.NewRequest(http.MethodPatch, "/scim/v2/Groups/"+created.ID, bytes.NewBufferString(removeMemberBody))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch remove member: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var afterRemove scim.SCIMGroup
	json.NewDecoder(rec.Body).Decode(&afterRemove)
	if len(afterRemove.Members) != 0 {
		t.Fatalf("expected 0 members after remove, got %d", len(afterRemove.Members))
	}
}

func TestPatchGroupNotFound(t *testing.T) {
	_, mux := setupHandler(t)

	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[]}`
	req := httptest.NewRequest(http.MethodPatch, "/scim/v2/Groups/nonexistent", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestGetGroupNotFound(t *testing.T) {
	_, mux := setupHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/scim/v2/Groups/nonexistent", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestDeleteGroupNotFound(t *testing.T) {
	_, mux := setupHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/scim/v2/Groups/nonexistent", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestCreateGroupWithInitialMembers(t *testing.T) {
	_, mux := setupHandler(t)

	// Create a user.
	userBody := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"gmember@example.com","displayName":"G Member","active":true}`
	req := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", bytes.NewBufferString(userBody))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var u scim.SCIMUser
	json.NewDecoder(rec.Body).Decode(&u)

	// Create group with initial members.
	body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"With Members","members":[{"value":"` + u.ID + `"}]}`
	req = httptest.NewRequest(http.MethodPost, "/scim/v2/Groups", bytes.NewBufferString(body))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var g scim.SCIMGroup
	json.NewDecoder(rec.Body).Decode(&g)
	if len(g.Members) != 1 {
		t.Fatalf("expected 1 member, got %d", len(g.Members))
	}
}

func TestCreateGroupMissingName(t *testing.T) {
	_, mux := setupHandler(t)

	body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"]}`
	req := httptest.NewRequest(http.MethodPost, "/scim/v2/Groups", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestCreateUserMissingUserName(t *testing.T) {
	_, mux := setupHandler(t)

	body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"displayName":"No Email"}`
	req := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestPatchUserNameParts(t *testing.T) {
	_, mux := setupHandler(t)

	// Create user.
	body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"nameparts@example.com","displayName":"John Doe","active":true}`
	req := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d", rec.Code)
	}
	var created scim.SCIMUser
	json.NewDecoder(rec.Body).Decode(&created)

	// Patch given name.
	patchBody := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"name.givenName","value":"Jane"}]}`
	req = httptest.NewRequest(http.MethodPatch, "/scim/v2/Users/"+created.ID, bytes.NewBufferString(patchBody))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch given name: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var patched scim.SCIMUser
	json.NewDecoder(rec.Body).Decode(&patched)
	if patched.DisplayName != "Jane Doe" {
		t.Errorf("displayName = %q, want 'Jane Doe'", patched.DisplayName)
	}

	// Patch family name.
	patchBody = `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"name.familyName","value":"Smith"}]}`
	req = httptest.NewRequest(http.MethodPatch, "/scim/v2/Users/"+patched.ID, bytes.NewBufferString(patchBody))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch family name: expected 200, got %d", rec.Code)
	}

	json.NewDecoder(rec.Body).Decode(&patched)
	if patched.DisplayName != "Jane Smith" {
		t.Errorf("displayName = %q, want 'Jane Smith'", patched.DisplayName)
	}

	// Patch with no path (map of attributes).
	patchBody = `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","value":{"displayName":"Direct Update"}}]}`
	req = httptest.NewRequest(http.MethodPatch, "/scim/v2/Users/"+patched.ID, bytes.NewBufferString(patchBody))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch no path: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	json.NewDecoder(rec.Body).Decode(&patched)
	if patched.DisplayName != "Direct Update" {
		t.Errorf("displayName = %q, want 'Direct Update'", patched.DisplayName)
	}
}

func TestPatchUserRemoveDisplayName(t *testing.T) {
	_, mux := setupHandler(t)

	// Create user.
	body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"rm@example.com","displayName":"To Remove","active":true}`
	req := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var created scim.SCIMUser
	json.NewDecoder(rec.Body).Decode(&created)

	// Remove displayName.
	patchBody := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"remove","path":"displayName"}]}`
	req = httptest.NewRequest(http.MethodPatch, "/scim/v2/Users/"+created.ID, bytes.NewBufferString(patchBody))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch remove: expected 200, got %d", rec.Code)
	}

	var patched scim.SCIMUser
	json.NewDecoder(rec.Body).Decode(&patched)
	if patched.DisplayName != "" {
		t.Errorf("displayName = %q, want empty", patched.DisplayName)
	}
}

func TestListUsersWithPagination(t *testing.T) {
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

	// Create 3 users.
	for i := 0; i < 3; i++ {
		body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"page` + string(rune('a'+i)) + `@example.com","displayName":"User","active":true}`
		req := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", bytes.NewBufferString(body))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
	}

	// List with pagination.
	req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users?startIndex=1&count=2", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp scim.SCIMListResponse
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp.TotalResults != 3 {
		t.Errorf("TotalResults = %d, want 3", resp.TotalResults)
	}
	if resp.ItemsPerPage != 2 {
		t.Errorf("ItemsPerPage = %d, want 2", resp.ItemsPerPage)
	}
}

func TestListUsersContainsFilter(t *testing.T) {
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

	// Create users.
	for _, email := range []string{"john@example.com", "jane@example.com"} {
		body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"` + email + `","displayName":"Test","active":true}`
		req := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", bytes.NewBufferString(body))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
	}

	// Filter with "co" operator.
	req := httptest.NewRequest(http.MethodGet, `/scim/v2/Users?filter=displayName+co+"Test"`, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp scim.SCIMListResponse
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp.TotalResults != 2 {
		t.Errorf("expected 2 results, got %d", resp.TotalResults)
	}
}
