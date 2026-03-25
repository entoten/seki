package oidc_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/entoten/seki/internal/oidc"
	"github.com/entoten/seki/internal/storage"

	_ "github.com/entoten/seki/internal/storage/sqlite"
)

type regHarness struct {
	store    storage.Storage
	provider *oidc.Provider
	mux      *http.ServeMux
}

func newRegHarness(t *testing.T) *regHarness {
	t.Helper()

	store, err := storage.New(storage.TestDatabaseConfig())
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	if err := store.Migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	signer := newTestSigner(t)
	provider := oidc.NewProvider("https://auth.example.com", signer, store)

	mux := http.NewServeMux()
	provider.RegisterRoutes(mux)

	return &regHarness{
		store:    store,
		provider: provider,
		mux:      mux,
	}
}

func (h *regHarness) doRegister(t *testing.T, body string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)
	return rec.Result()
}

func TestRegistration_CreateClient(t *testing.T) {
	h := newRegHarness(t)

	body := `{
		"redirect_uris": ["https://app.example.com/callback"],
		"client_name": "My Dynamic App",
		"grant_types": ["authorization_code"],
		"response_types": ["code"],
		"token_endpoint_auth_method": "client_secret_basic"
	}`

	resp := h.doRegister(t, body)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 201, got %d: %s", resp.StatusCode, string(b))
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	// Verify all required fields are present.
	if result["client_id"] == nil || result["client_id"].(string) == "" {
		t.Error("missing client_id")
	}
	if result["client_secret"] == nil || result["client_secret"].(string) == "" {
		t.Error("missing client_secret")
	}
	if result["registration_access_token"] == nil || result["registration_access_token"].(string) == "" {
		t.Error("missing registration_access_token")
	}
	if result["registration_client_uri"] == nil || result["registration_client_uri"].(string) == "" {
		t.Error("missing registration_client_uri")
	}
	if result["client_name"].(string) != "My Dynamic App" {
		t.Errorf("client_name = %q, want My Dynamic App", result["client_name"])
	}
}

func TestRegistration_ReadClient(t *testing.T) {
	h := newRegHarness(t)

	// Register a client first.
	body := `{
		"redirect_uris": ["https://app.example.com/callback"],
		"client_name": "Read Test App",
		"grant_types": ["authorization_code"]
	}`
	resp := h.doRegister(t, body)
	defer resp.Body.Close()

	var created map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&created)

	clientID := created["client_id"].(string)
	rat := created["registration_access_token"].(string)

	// Read the client.
	req := httptest.NewRequest(http.MethodGet, "/register/"+clientID, nil)
	req.Header.Set("Authorization", "Bearer "+rat)
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)

	readResp := rec.Result()
	defer readResp.Body.Close()

	if readResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(readResp.Body)
		t.Fatalf("expected 200, got %d: %s", readResp.StatusCode, string(b))
	}

	var readResult map[string]interface{}
	_ = json.NewDecoder(readResp.Body).Decode(&readResult)

	if readResult["client_id"].(string) != clientID {
		t.Errorf("client_id = %q, want %q", readResult["client_id"], clientID)
	}
	if readResult["client_name"].(string) != "Read Test App" {
		t.Errorf("client_name = %q, want Read Test App", readResult["client_name"])
	}
}

func TestRegistration_UpdateClient(t *testing.T) {
	h := newRegHarness(t)

	// Register a client first.
	body := `{
		"redirect_uris": ["https://app.example.com/callback"],
		"client_name": "Original Name",
		"grant_types": ["authorization_code"]
	}`
	resp := h.doRegister(t, body)
	defer resp.Body.Close()

	var created map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&created)

	clientID := created["client_id"].(string)
	rat := created["registration_access_token"].(string)

	// Update the client.
	updateBody := `{
		"client_name": "Updated Name",
		"redirect_uris": ["https://new.example.com/callback"]
	}`
	req := httptest.NewRequest(http.MethodPut, "/register/"+clientID, strings.NewReader(updateBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+rat)
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)

	updateResp := rec.Result()
	defer updateResp.Body.Close()

	if updateResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(updateResp.Body)
		t.Fatalf("expected 200, got %d: %s", updateResp.StatusCode, string(b))
	}

	var updated map[string]interface{}
	_ = json.NewDecoder(updateResp.Body).Decode(&updated)

	if updated["client_name"].(string) != "Updated Name" {
		t.Errorf("client_name = %q, want Updated Name", updated["client_name"])
	}
}

func TestRegistration_DeleteClient(t *testing.T) {
	h := newRegHarness(t)

	// Register a client first.
	body := `{
		"redirect_uris": ["https://app.example.com/callback"],
		"client_name": "Delete Me",
		"grant_types": ["authorization_code"]
	}`
	resp := h.doRegister(t, body)
	defer resp.Body.Close()

	var created map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&created)

	clientID := created["client_id"].(string)
	rat := created["registration_access_token"].(string)

	// Delete the client.
	req := httptest.NewRequest(http.MethodDelete, "/register/"+clientID, nil)
	req.Header.Set("Authorization", "Bearer "+rat)
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)

	deleteResp := rec.Result()
	defer deleteResp.Body.Close()

	if deleteResp.StatusCode != http.StatusNoContent {
		b, _ := io.ReadAll(deleteResp.Body)
		t.Fatalf("expected 204, got %d: %s", deleteResp.StatusCode, string(b))
	}

	// Verify the client is gone.
	_, err := h.store.GetClient(req.Context(), clientID)
	if err != storage.ErrNotFound {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
}

func TestRegistration_InvalidRAT(t *testing.T) {
	h := newRegHarness(t)

	// Register a client first.
	body := `{
		"redirect_uris": ["https://app.example.com/callback"],
		"client_name": "RAT Test",
		"grant_types": ["authorization_code"]
	}`
	resp := h.doRegister(t, body)
	defer resp.Body.Close()

	var created map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&created)

	clientID := created["client_id"].(string)

	// Try to read with wrong RAT.
	req := httptest.NewRequest(http.MethodGet, "/register/"+clientID, nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)

	readResp := rec.Result()
	defer readResp.Body.Close()

	if readResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for invalid RAT, got %d", readResp.StatusCode)
	}
}

func TestRegistration_MissingRAT(t *testing.T) {
	h := newRegHarness(t)

	// Register a client first.
	body := `{
		"redirect_uris": ["https://app.example.com/callback"],
		"client_name": "No RAT Test",
		"grant_types": ["authorization_code"]
	}`
	resp := h.doRegister(t, body)
	defer resp.Body.Close()

	var created map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&created)

	clientID := created["client_id"].(string)

	// Try to read without Authorization header.
	req := httptest.NewRequest(http.MethodGet, "/register/"+clientID, nil)
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)

	readResp := rec.Result()
	defer readResp.Body.Close()

	if readResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing RAT, got %d", readResp.StatusCode)
	}
}
