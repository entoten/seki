package migrate

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Monet/seki/pkg/client"
)

func TestParseAuth0Export_UserArray(t *testing.T) {
	input := `[
		{
			"user_id": "auth0|123",
			"email": "alice@example.com",
			"email_verified": true,
			"name": "Alice Smith",
			"created_at": "2024-01-01T00:00:00.000Z"
		},
		{
			"user_id": "auth0|456",
			"email": "bob@example.com",
			"email_verified": false,
			"name": "Bob Jones"
		}
	]`

	export, err := parseAuth0ExportReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(export.Users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(export.Users))
	}

	if export.Users[0].Email != "alice@example.com" {
		t.Errorf("expected alice@example.com, got %s", export.Users[0].Email)
	}
	if export.Users[0].UserID != "auth0|123" {
		t.Errorf("expected auth0|123, got %s", export.Users[0].UserID)
	}
	if !export.Users[0].EmailVerified {
		t.Error("expected email_verified to be true")
	}
	if export.Users[1].Name != "Bob Jones" {
		t.Errorf("expected Bob Jones, got %s", export.Users[1].Name)
	}
}

func TestParseAuth0Export_ObjectFormat(t *testing.T) {
	input := `{
		"users": [
			{
				"user_id": "auth0|789",
				"email": "carol@example.com",
				"name": "Carol"
			}
		],
		"clients": [
			{
				"client_id": "spa-app",
				"name": "My SPA",
				"app_type": "spa",
				"callbacks": ["http://localhost:3000/callback"],
				"grant_types": ["authorization_code"]
			}
		]
	}`

	export, err := parseAuth0ExportReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(export.Users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(export.Users))
	}
	if export.Users[0].Email != "carol@example.com" {
		t.Errorf("expected carol@example.com, got %s", export.Users[0].Email)
	}

	if len(export.Clients) != 1 {
		t.Fatalf("expected 1 client, got %d", len(export.Clients))
	}
	if export.Clients[0].Name != "My SPA" {
		t.Errorf("expected My SPA, got %s", export.Clients[0].Name)
	}
	if export.Clients[0].ClientID != "spa-app" {
		t.Errorf("expected spa-app, got %s", export.Clients[0].ClientID)
	}
}

func TestParseAuth0Export_MissingFields(t *testing.T) {
	input := `[{"user_id": "auth0|100"}]`

	export, err := parseAuth0ExportReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(export.Users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(export.Users))
	}
	if export.Users[0].Email != "" {
		t.Errorf("expected empty email, got %s", export.Users[0].Email)
	}
	if export.Users[0].Name != "" {
		t.Errorf("expected empty name, got %s", export.Users[0].Name)
	}
}

func TestParseAuth0Export_InvalidJSON(t *testing.T) {
	_, err := parseAuth0ExportReader(strings.NewReader("{invalid"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestBuildAuth0UserMetadata(t *testing.T) {
	u := Auth0User{
		UserID:      "auth0|123",
		AppMetadata: json.RawMessage(`{"plan":"pro"}`),
	}

	meta := buildAuth0UserMetadata(u)
	var m map[string]interface{}
	if err := json.Unmarshal(meta, &m); err != nil {
		t.Fatalf("unmarshal metadata: %v", err)
	}

	if m["auth0_user_id"] != "auth0|123" {
		t.Errorf("expected auth0|123, got %v", m["auth0_user_id"])
	}
	am, ok := m["auth0_app_metadata"].(map[string]interface{})
	if !ok {
		t.Fatal("expected auth0_app_metadata to be a map")
	}
	if am["plan"] != "pro" {
		t.Errorf("expected plan=pro, got %v", am["plan"])
	}
}

func TestAuth0Importer_DryRun(t *testing.T) {
	// Mock API server that returns empty user lists (no existing users).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/users" && r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"users":       []interface{}{},
				"next_cursor": "",
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	apiClient := client.New(srv.URL, "test-key")
	export := &Auth0Export{
		Users: []Auth0User{
			{UserID: "auth0|1", Email: "new@example.com", Name: "New User"},
			{UserID: "auth0|2", Email: "another@example.com", Name: "Another"},
		},
		Clients: []Auth0Client{
			{ClientID: "app1", Name: "My App"},
		},
	}

	var buf bytes.Buffer
	importer := NewAuth0Importer(export, Config{
		APIClient: apiClient,
		DryRun:    true,
	}, &buf)

	result, err := importer.Import(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "DRY RUN") {
		t.Error("expected DRY RUN header in output")
	}
	if !strings.Contains(output, "new@example.com") {
		t.Error("expected new@example.com in output")
	}
	if !strings.Contains(output, "My App") {
		t.Error("expected client name in output")
	}

	if result.UsersCreated != 2 {
		t.Errorf("expected 2 users to create, got %d", result.UsersCreated)
	}
	if result.ClientsCreated != 1 {
		t.Errorf("expected 1 client to create, got %d", result.ClientsCreated)
	}
}

func TestAuth0Importer_DryRun_SkipsExisting(t *testing.T) {
	// Mock API server that returns one existing user.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/users" && r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"users": []map[string]interface{}{
					{"id": "seki-1", "email": "existing@example.com"},
				},
				"next_cursor": "",
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	apiClient := client.New(srv.URL, "test-key")
	export := &Auth0Export{
		Users: []Auth0User{
			{UserID: "auth0|1", Email: "existing@example.com", Name: "Existing"},
			{UserID: "auth0|2", Email: "new@example.com", Name: "New"},
		},
	}

	var buf bytes.Buffer
	importer := NewAuth0Importer(export, Config{
		APIClient: apiClient,
		DryRun:    true,
	}, &buf)

	result, err := importer.Import(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.UsersCreated != 1 {
		t.Errorf("expected 1 user to create, got %d", result.UsersCreated)
	}
	if result.UsersSkipped != 1 {
		t.Errorf("expected 1 user to skip, got %d", result.UsersSkipped)
	}

	output := buf.String()
	if !strings.Contains(output, "SKIP") {
		t.Error("expected SKIP in output for existing user")
	}
}

func TestAuth0Importer_LiveImport(t *testing.T) {
	var createdUsers []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/users" && r.Method == http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"users":       []interface{}{},
				"next_cursor": "",
			})
		case r.URL.Path == "/api/v1/users" && r.Method == http.MethodPost:
			var input map[string]interface{}
			json.NewDecoder(r.Body).Decode(&input)
			createdUsers = append(createdUsers, input["email"].(string))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id":    "seki-new",
				"email": input["email"],
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	apiClient := client.New(srv.URL, "test-key")
	export := &Auth0Export{
		Users: []Auth0User{
			{UserID: "auth0|1", Email: "new@example.com", Name: "New User"},
		},
	}

	var buf bytes.Buffer
	importer := NewAuth0Importer(export, Config{
		APIClient: apiClient,
		Verbose:   true,
	}, &buf)

	result, err := importer.Import(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.UsersCreated != 1 {
		t.Errorf("expected 1 user created, got %d", result.UsersCreated)
	}
	if len(createdUsers) != 1 || createdUsers[0] != "new@example.com" {
		t.Errorf("expected new@example.com to be created, got %v", createdUsers)
	}
}
