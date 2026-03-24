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

func TestParseKeycloakExport(t *testing.T) {
	input := `{
		"realm": "my-realm",
		"users": [
			{
				"id": "kc-user-1",
				"username": "alice",
				"email": "alice@example.com",
				"emailVerified": true,
				"enabled": true,
				"firstName": "Alice",
				"lastName": "Smith",
				"credentials": [
					{"type": "password", "value": "$2a$10$abcdefghijklmnopqrstuv"}
				],
				"realmRoles": ["admin"],
				"groups": ["/engineering"]
			},
			{
				"id": "kc-user-2",
				"username": "bob@example.com",
				"emailVerified": false,
				"enabled": true,
				"firstName": "Bob",
				"lastName": "Jones"
			}
		],
		"clients": [
			{
				"clientId": "my-spa",
				"name": "My SPA App",
				"enabled": true,
				"publicClient": true,
				"redirectUris": ["http://localhost:3000/*"],
				"protocol": "openid-connect"
			},
			{
				"clientId": "disabled-client",
				"name": "Disabled",
				"enabled": false,
				"protocol": "openid-connect"
			}
		],
		"roles": {
			"realm": [
				{"id": "role-1", "name": "admin", "description": "Administrator"},
				{"id": "role-2", "name": "offline_access"},
				{"id": "role-3", "name": "editor", "description": "Editor role"}
			]
		},
		"groups": [
			{
				"id": "grp-1",
				"name": "Engineering",
				"path": "/engineering",
				"subGroups": []
			}
		]
	}`

	export, err := parseKeycloakExportReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if export.Realm != "my-realm" {
		t.Errorf("expected realm my-realm, got %s", export.Realm)
	}

	// Users.
	if len(export.Users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(export.Users))
	}
	if export.Users[0].Email != "alice@example.com" {
		t.Errorf("expected alice@example.com, got %s", export.Users[0].Email)
	}
	if export.Users[0].FirstName != "Alice" {
		t.Errorf("expected Alice, got %s", export.Users[0].FirstName)
	}
	if len(export.Users[0].Credentials) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(export.Users[0].Credentials))
	}
	if export.Users[0].Credentials[0].Type != "password" {
		t.Errorf("expected password credential type, got %s", export.Users[0].Credentials[0].Type)
	}

	// Clients.
	if len(export.Clients) != 2 {
		t.Fatalf("expected 2 clients, got %d", len(export.Clients))
	}
	if export.Clients[0].Name != "My SPA App" {
		t.Errorf("expected My SPA App, got %s", export.Clients[0].Name)
	}

	// Roles.
	if export.Roles == nil {
		t.Fatal("expected roles to be present")
	}
	if len(export.Roles.Realm) != 3 {
		t.Fatalf("expected 3 realm roles, got %d", len(export.Roles.Realm))
	}

	// Groups.
	if len(export.Groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(export.Groups))
	}
	if export.Groups[0].Name != "Engineering" {
		t.Errorf("expected Engineering, got %s", export.Groups[0].Name)
	}
}

func TestParseKeycloakExport_InvalidJSON(t *testing.T) {
	_, err := parseKeycloakExportReader(strings.NewReader("not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestKeycloakUserEmail_Fallback(t *testing.T) {
	tests := []struct {
		name     string
		user     KeycloakUser
		expected string
	}{
		{
			name:     "has email",
			user:     KeycloakUser{Email: "a@b.com", Username: "alice"},
			expected: "a@b.com",
		},
		{
			name:     "username is email",
			user:     KeycloakUser{Username: "bob@example.com"},
			expected: "bob@example.com",
		},
		{
			name:     "no email",
			user:     KeycloakUser{Username: "charlie"},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := keycloakUserEmail(tt.user)
			if got != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}

func TestKeycloakDisplayName(t *testing.T) {
	tests := []struct {
		name     string
		user     KeycloakUser
		expected string
	}{
		{
			name:     "first and last",
			user:     KeycloakUser{FirstName: "Alice", LastName: "Smith"},
			expected: "Alice Smith",
		},
		{
			name:     "first only",
			user:     KeycloakUser{FirstName: "Bob"},
			expected: "Bob",
		},
		{
			name:     "username fallback",
			user:     KeycloakUser{Username: "charlie"},
			expected: "charlie",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := keycloakDisplayName(tt.user)
			if got != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}

func TestIsKeycloakDefaultRole(t *testing.T) {
	if !isKeycloakDefaultRole("offline_access") {
		t.Error("expected offline_access to be a default role")
	}
	if !isKeycloakDefaultRole("uma_authorization") {
		t.Error("expected uma_authorization to be a default role")
	}
	if !isKeycloakDefaultRole("default-roles-myrealm") {
		t.Error("expected default-roles-myrealm to be a default role")
	}
	if isKeycloakDefaultRole("admin") {
		t.Error("expected admin NOT to be a default role")
	}
}

func TestSlugify(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Engineering", "engineering"},
		{"My Team  Name", "my-team-name"},
		{"hello-world", "hello-world"},
		{"  spaces  ", "spaces"},
		{"foo/bar", "foo-bar"},
		{"", "unnamed"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := slugify(tt.input)
			if got != tt.expected {
				t.Errorf("slugify(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestKeycloakImporter_DryRun(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/users" && r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"users":       []interface{}{},
				"next_cursor": "",
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	apiClient := client.New(srv.URL, "test-key")
	export := &KeycloakRealmExport{
		Realm: "test-realm",
		Users: []KeycloakUser{
			{ID: "kc-1", Email: "alice@example.com", FirstName: "Alice", LastName: "Smith", Enabled: true},
			{ID: "kc-2", Username: "bob@example.com", FirstName: "Bob", Enabled: true},
		},
		Clients: []KeycloakClient{
			{ClientID: "spa", Name: "SPA App", Enabled: true, Protocol: "openid-connect"},
		},
		Roles: &KeycloakRoles{
			Realm: []KeycloakRole{
				{ID: "r1", Name: "admin"},
				{ID: "r2", Name: "offline_access"},
			},
		},
		Groups: []KeycloakGroup{
			{ID: "g1", Name: "Engineering"},
		},
	}

	var buf bytes.Buffer
	importer := NewKeycloakImporter(export, Config{
		APIClient: apiClient,
		DryRun:    true,
	}, &buf)

	result, err := importer.Import(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "DRY RUN") {
		t.Error("expected DRY RUN header")
	}
	if !strings.Contains(output, "alice@example.com") {
		t.Error("expected alice@example.com in output")
	}
	if !strings.Contains(output, "Engineering") {
		t.Error("expected Engineering org in output")
	}
	// offline_access should be filtered out.
	if strings.Contains(output, "offline_access") {
		t.Error("expected offline_access to be filtered out")
	}

	if result.UsersCreated != 2 {
		t.Errorf("expected 2 users to create, got %d", result.UsersCreated)
	}
	if result.ClientsCreated != 1 {
		t.Errorf("expected 1 client to create, got %d", result.ClientsCreated)
	}
	if result.RolesCreated != 1 {
		t.Errorf("expected 1 role to create (admin only), got %d", result.RolesCreated)
	}
	if result.OrgsCreated != 1 {
		t.Errorf("expected 1 org to create, got %d", result.OrgsCreated)
	}
}

func TestKeycloakImporter_LiveImport(t *testing.T) {
	var createdUsers []string
	var createdOrgs []string
	var createdRoles []string
	var createdClients []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/v1/users" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"users":       []interface{}{},
				"next_cursor": "",
			})
		case r.URL.Path == "/api/v1/users" && r.Method == http.MethodPost:
			var input map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&input)
			createdUsers = append(createdUsers, input["email"].(string))
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"id": "u1", "email": input["email"]})
		case r.URL.Path == "/api/v1/orgs" && r.Method == http.MethodPost:
			var input map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&input)
			createdOrgs = append(createdOrgs, input["name"].(string))
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"id": "o1", "slug": input["slug"], "name": input["name"]})
		case strings.HasSuffix(r.URL.Path, "/roles") && r.Method == http.MethodPost:
			var input map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&input)
			createdRoles = append(createdRoles, input["name"].(string))
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"id": "r1", "name": input["name"]})
		case r.URL.Path == "/api/v1/clients" && r.Method == http.MethodPost:
			var input map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&input)
			createdClients = append(createdClients, input["name"].(string))
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"id": input["id"], "name": input["name"]})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	apiClient := client.New(srv.URL, "test-key")
	export := &KeycloakRealmExport{
		Realm: "test",
		Users: []KeycloakUser{
			{ID: "kc-1", Email: "alice@example.com", FirstName: "Alice", LastName: "Smith"},
		},
		Clients: []KeycloakClient{
			{ClientID: "spa", Name: "SPA", Enabled: true, Protocol: "openid-connect"},
		},
		Roles: &KeycloakRoles{
			Realm: []KeycloakRole{
				{ID: "r1", Name: "editor"},
			},
		},
		Groups: []KeycloakGroup{
			{ID: "g1", Name: "Engineering"},
		},
	}

	var buf bytes.Buffer
	importer := NewKeycloakImporter(export, Config{
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
	if result.OrgsCreated != 1 {
		t.Errorf("expected 1 org created, got %d", result.OrgsCreated)
	}
	if result.RolesCreated != 1 {
		t.Errorf("expected 1 role created, got %d", result.RolesCreated)
	}
	if result.ClientsCreated != 1 {
		t.Errorf("expected 1 client created, got %d", result.ClientsCreated)
	}

	if len(createdUsers) != 1 || createdUsers[0] != "alice@example.com" {
		t.Errorf("unexpected created users: %v", createdUsers)
	}
	if len(createdOrgs) != 1 || createdOrgs[0] != "Engineering" {
		t.Errorf("unexpected created orgs: %v", createdOrgs)
	}
	if len(createdRoles) != 1 || createdRoles[0] != "editor" {
		t.Errorf("unexpected created roles: %v", createdRoles)
	}
	if len(createdClients) != 1 || createdClients[0] != "SPA" {
		t.Errorf("unexpected created clients: %v", createdClients)
	}
}

func TestKeycloakImporter_CredentialFormats(t *testing.T) {
	input := `{
		"realm": "test",
		"users": [
			{
				"id": "kc-1",
				"username": "alice",
				"email": "alice@example.com",
				"enabled": true,
				"credentials": [
					{"type": "password", "value": "$2a$10$hash1", "algorithm": "bcrypt"},
					{"type": "password", "value": "pbkdf2hash", "algorithm": "pbkdf2-sha256"}
				]
			}
		]
	}`

	export, err := parseKeycloakExportReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(export.Users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(export.Users))
	}
	if len(export.Users[0].Credentials) != 2 {
		t.Fatalf("expected 2 credentials, got %d", len(export.Users[0].Credentials))
	}
	if export.Users[0].Credentials[0].Algorithm != "bcrypt" {
		t.Errorf("expected bcrypt, got %s", export.Users[0].Credentials[0].Algorithm)
	}
	if export.Users[0].Credentials[1].Algorithm != "pbkdf2-sha256" {
		t.Errorf("expected pbkdf2-sha256, got %s", export.Users[0].Credentials[1].Algorithm)
	}
}
