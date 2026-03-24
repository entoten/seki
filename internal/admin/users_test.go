package admin_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/entoten/seki/internal/admin"
	"github.com/entoten/seki/internal/storage"
	_ "github.com/entoten/seki/internal/storage/sqlite"
)

func setupHandler(t *testing.T) *admin.Handler {
	t.Helper()
	s, err := storage.New(storage.TestDatabaseConfig())
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := s.Migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return admin.NewHandler(s)
}

func newMux(h *admin.Handler) *http.ServeMux {
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	return mux
}

func TestCreateUser(t *testing.T) {
	h := setupHandler(t)
	mux := newMux(h)

	body := `{"email":"alice@example.com","display_name":"Alice","metadata":{"role":"admin"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var user storage.User
	if err := json.NewDecoder(rec.Body).Decode(&user); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if user.ID == "" {
		t.Fatal("expected non-empty ID")
	}
	if user.Email != "alice@example.com" {
		t.Fatalf("email mismatch: %s", user.Email)
	}
	if user.DisplayName != "Alice" {
		t.Fatalf("display_name mismatch: %s", user.DisplayName)
	}
}

func TestCreateUserDuplicateEmail(t *testing.T) {
	h := setupHandler(t)
	mux := newMux(h)

	body := `{"email":"dup@example.com","display_name":"First"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("first create expected 201, got %d", rec.Code)
	}

	// Second create with same email.
	req = httptest.NewRequest(http.MethodPost, "/api/v1/users", bytes.NewBufferString(body))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestGetUser(t *testing.T) {
	h := setupHandler(t)
	mux := newMux(h)

	// Create a user first.
	body := `{"email":"bob@example.com","display_name":"Bob"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create expected 201, got %d", rec.Code)
	}
	var created storage.User
	_ = json.NewDecoder(rec.Body).Decode(&created)

	// Get the user.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/users/"+created.ID, nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var got storage.User
	_ = json.NewDecoder(rec.Body).Decode(&got)
	if got.Email != "bob@example.com" {
		t.Fatalf("email mismatch: %s", got.Email)
	}
	if got.DisplayName != "Bob" {
		t.Fatalf("display_name mismatch: %s", got.DisplayName)
	}
}

func TestGetUserNotFound(t *testing.T) {
	h := setupHandler(t)
	mux := newMux(h)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/nonexistent", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}

	var problem admin.ProblemDetail
	_ = json.NewDecoder(rec.Body).Decode(&problem)
	if problem.Status != 404 {
		t.Fatalf("problem status mismatch: %d", problem.Status)
	}
}

func TestListUsersWithPagination(t *testing.T) {
	h := setupHandler(t)
	mux := newMux(h)

	// Create 3 users.
	for i := 0; i < 3; i++ {
		body := `{"email":"page` + itoa(i) + `@example.com","display_name":"User"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/users", bytes.NewBufferString(body))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("create user %d: expected 201, got %d", i, rec.Code)
		}
	}

	// List with limit=2.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users?limit=2", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var page1 struct {
		Users      []storage.User `json:"users"`
		NextCursor string         `json:"next_cursor"`
	}
	_ = json.NewDecoder(rec.Body).Decode(&page1)
	if len(page1.Users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(page1.Users))
	}
	if page1.NextCursor == "" {
		t.Fatal("expected non-empty next_cursor")
	}

	// Page 2.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/users?limit=2&cursor="+page1.NextCursor, nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("page 2: expected 200, got %d", rec.Code)
	}

	var page2 struct {
		Users      []storage.User `json:"users"`
		NextCursor string         `json:"next_cursor"`
	}
	_ = json.NewDecoder(rec.Body).Decode(&page2)
	if len(page2.Users) != 1 {
		t.Fatalf("expected 1 user on page 2, got %d", len(page2.Users))
	}
	if page2.NextCursor != "" {
		t.Fatalf("expected empty next_cursor on last page, got %q", page2.NextCursor)
	}
}

func TestListUsersWithEmailFilter(t *testing.T) {
	h := setupHandler(t)
	mux := newMux(h)

	// Create 2 users.
	for _, email := range []string{"filter1@example.com", "filter2@example.com"} {
		body := `{"email":"` + email + `","display_name":"Test"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/users", bytes.NewBufferString(body))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("create: expected 201, got %d", rec.Code)
		}
	}

	// Filter by email.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users?email=filter1@example.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp struct {
		Users []storage.User `json:"users"`
	}
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if len(resp.Users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(resp.Users))
	}
	if resp.Users[0].Email != "filter1@example.com" {
		t.Fatalf("email mismatch: %s", resp.Users[0].Email)
	}

	// Filter by non-existent email returns empty list.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/users?email=nobody@example.com", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if len(resp.Users) != 0 {
		t.Fatalf("expected 0 users, got %d", len(resp.Users))
	}
}

func TestUpdateUserPartialFields(t *testing.T) {
	h := setupHandler(t)
	mux := newMux(h)

	// Create user.
	body := `{"email":"update@example.com","display_name":"Original","metadata":{"key":"val"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d", rec.Code)
	}
	var created storage.User
	_ = json.NewDecoder(rec.Body).Decode(&created)

	// Partial update: only display_name.
	patchBody := `{"display_name":"Updated"}`
	req = httptest.NewRequest(http.MethodPatch, "/api/v1/users/"+created.ID, bytes.NewBufferString(patchBody))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var updated storage.User
	_ = json.NewDecoder(rec.Body).Decode(&updated)
	if updated.DisplayName != "Updated" {
		t.Fatalf("display_name not updated: %s", updated.DisplayName)
	}
	if updated.Email != "update@example.com" {
		t.Fatalf("email should be unchanged: %s", updated.Email)
	}

	// Partial update: disabled field.
	patchBody = `{"disabled":true}`
	req = httptest.NewRequest(http.MethodPatch, "/api/v1/users/"+created.ID, bytes.NewBufferString(patchBody))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch disabled: expected 200, got %d", rec.Code)
	}
	_ = json.NewDecoder(rec.Body).Decode(&updated)
	if !updated.Disabled {
		t.Fatal("disabled should be true")
	}
	if updated.DisplayName != "Updated" {
		t.Fatalf("display_name should still be Updated: %s", updated.DisplayName)
	}
}

func TestDeleteUser(t *testing.T) {
	h := setupHandler(t)
	mux := newMux(h)

	// Create user.
	body := `{"email":"delete@example.com","display_name":"ToDelete"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d", rec.Code)
	}
	var created storage.User
	_ = json.NewDecoder(rec.Body).Decode(&created)

	// Delete.
	req = httptest.NewRequest(http.MethodDelete, "/api/v1/users/"+created.ID, nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rec.Code)
	}

	// Verify it's gone.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/users/"+created.ID, nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 after delete, got %d", rec.Code)
	}
}

func TestDeleteUserNotFound(t *testing.T) {
	h := setupHandler(t)
	mux := newMux(h)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/nonexistent", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func itoa(i int) string {
	return strconv.Itoa(i)
}
