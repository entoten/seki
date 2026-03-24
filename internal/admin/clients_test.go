package admin_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientCRUDViaAPI(t *testing.T) {
	h := setupHandler(t)
	mux := newMux(h)

	// Create client
	body := `{"id":"my-app","name":"My Application","redirect_uris":["https://app.example.com/callback"],"grant_types":["authorization_code"],"scopes":["openid","profile"],"pkce_required":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/clients", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create client: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var client map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&client)
	if client["id"] != "my-app" {
		t.Fatalf("id mismatch: %v", client["id"])
	}
	if client["name"] != "My Application" {
		t.Fatalf("name mismatch: %v", client["name"])
	}
	if client["pkce_required"] != true {
		t.Fatalf("pkce_required mismatch: %v", client["pkce_required"])
	}

	// Get client by ID
	req = httptest.NewRequest(http.MethodGet, "/api/v1/clients/my-app", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get client: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var fetched map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&fetched)
	if fetched["id"] != "my-app" {
		t.Fatalf("fetched id mismatch: %v", fetched["id"])
	}

	// List clients
	req = httptest.NewRequest(http.MethodGet, "/api/v1/clients", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list clients: expected 200, got %d", rec.Code)
	}
	var listResp map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&listResp)
	data := listResp["data"].([]any)
	if len(data) != 1 {
		t.Fatalf("expected 1 client, got %d", len(data))
	}

	// Get non-existent client
	req = httptest.NewRequest(http.MethodGet, "/api/v1/clients/nonexistent", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}

	// Delete client
	req = httptest.NewRequest(http.MethodDelete, "/api/v1/clients/my-app", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete client: expected 204, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify deleted
	req = httptest.NewRequest(http.MethodGet, "/api/v1/clients/my-app", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 after delete, got %d", rec.Code)
	}
}

func TestDuplicateClientReturns409(t *testing.T) {
	h := setupHandler(t)
	mux := newMux(h)

	body := `{"id":"dup-client","name":"Client 1"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/clients", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("first create: expected 201, got %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/clients", bytes.NewBufferString(body))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate client: expected 409, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestCreateClientValidation(t *testing.T) {
	h := setupHandler(t)
	mux := newMux(h)

	// Missing id
	body := `{"name":"No ID"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/clients", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing id: expected 400, got %d", rec.Code)
	}

	// Missing name
	body = `{"id":"no-name"}`
	req = httptest.NewRequest(http.MethodPost, "/api/v1/clients", bytes.NewBufferString(body))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing name: expected 400, got %d", rec.Code)
	}
}
