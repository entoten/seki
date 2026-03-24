package migrate

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/entoten/seki/pkg/client"
)

func TestParseOktaExport(t *testing.T) {
	input := `{
		"users": [
			{
				"id": "00u1abc",
				"status": "ACTIVE",
				"profile": {
					"login": "alice@company.com",
					"email": "alice@company.com",
					"firstName": "Alice",
					"lastName": "Smith"
				}
			},
			{
				"id": "00u2def",
				"status": "SUSPENDED",
				"profile": {
					"login": "bob@company.com",
					"email": "bob@company.com",
					"firstName": "Bob",
					"lastName": "Jones"
				}
			}
		],
		"groups": [
			{
				"id": "00g1abc",
				"profile": { "name": "Engineering", "description": "Eng team" },
				"users": ["00u1abc"]
			}
		],
		"applications": [
			{
				"id": "0oa1abc",
				"name": "my-app",
				"label": "My Application",
				"signOnMode": "OPENID_CONNECT",
				"settings": {
					"oauthClient": {
						"redirect_uris": ["https://app.example.com/callback"],
						"grant_types": ["authorization_code"]
					}
				}
			},
			{
				"id": "0oa2def",
				"name": "saml-app",
				"label": "SAML App",
				"signOnMode": "SAML_2_0"
			}
		]
	}`

	export, err := parseOktaExportReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(export.Users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(export.Users))
	}
	if export.Users[0].Profile.Email != "alice@company.com" {
		t.Errorf("expected alice@company.com, got %s", export.Users[0].Profile.Email)
	}
	if export.Users[0].ID != "00u1abc" {
		t.Errorf("expected 00u1abc, got %s", export.Users[0].ID)
	}

	if len(export.Groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(export.Groups))
	}
	if export.Groups[0].Profile.Name != "Engineering" {
		t.Errorf("expected Engineering, got %s", export.Groups[0].Profile.Name)
	}
	if len(export.Groups[0].Users) != 1 {
		t.Fatalf("expected 1 group member, got %d", len(export.Groups[0].Users))
	}

	if len(export.Applications) != 2 {
		t.Fatalf("expected 2 applications, got %d", len(export.Applications))
	}
	if export.Applications[0].Label != "My Application" {
		t.Errorf("expected My Application, got %s", export.Applications[0].Label)
	}
	if export.Applications[0].Settings.OAuthClient == nil {
		t.Fatal("expected oauthClient settings to be present")
	}
	if len(export.Applications[0].Settings.OAuthClient.RedirectURIs) != 1 {
		t.Fatalf("expected 1 redirect URI, got %d", len(export.Applications[0].Settings.OAuthClient.RedirectURIs))
	}
}

func TestParseOktaExport_InvalidJSON(t *testing.T) {
	_, err := parseOktaExportReader(strings.NewReader("{invalid"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestOktaUserMapping(t *testing.T) {
	u := OktaUser{
		ID:     "00u1",
		Status: "ACTIVE",
		Profile: OktaProfile{
			Login:     "alice@company.com",
			Email:     "alice@company.com",
			FirstName: "Alice",
			LastName:  "Smith",
		},
	}

	email := oktaUserEmail(u)
	if email != "alice@company.com" {
		t.Errorf("expected alice@company.com, got %s", email)
	}

	display := oktaDisplayName(u)
	if display != "Alice Smith" {
		t.Errorf("expected Alice Smith, got %s", display)
	}

	// Test login fallback when email is empty.
	u2 := OktaUser{
		Profile: OktaProfile{Login: "bob@company.com"},
	}
	if oktaUserEmail(u2) != "bob@company.com" {
		t.Errorf("expected login fallback, got %s", oktaUserEmail(u2))
	}

	// Test empty email and non-email login.
	u3 := OktaUser{
		Profile: OktaProfile{Login: "charlie"},
	}
	if oktaUserEmail(u3) != "" {
		t.Errorf("expected empty email, got %s", oktaUserEmail(u3))
	}
}

func TestOktaStatusMapping(t *testing.T) {
	tests := []struct {
		status   string
		disabled bool
	}{
		{"ACTIVE", false},
		{"STAGED", false},
		{"SUSPENDED", true},
		{"DEPROVISIONED", true},
		{"LOCKED_OUT", true},
		{"RECOVERY", true},
		{"PASSWORD_EXPIRED", true},
	}

	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			got := oktaStatusDisabled(tt.status)
			if got != tt.disabled {
				t.Errorf("oktaStatusDisabled(%q) = %v, want %v", tt.status, got, tt.disabled)
			}
		})
	}
}

func TestOktaGroupToOrgMapping(t *testing.T) {
	g := OktaGroup{
		ID: "00g1",
		Profile: OktaGroupProfile{
			Name:        "Engineering Team",
			Description: "The engineering team",
		},
		Users: []string{"00u1", "00u2"},
	}

	slug := slugify(g.Profile.Name)
	if slug != "engineering-team" {
		t.Errorf("expected engineering-team, got %s", slug)
	}
	if len(g.Users) != 2 {
		t.Errorf("expected 2 group members, got %d", len(g.Users))
	}
}

func TestOktaAppToClientMapping(t *testing.T) {
	app := OktaApplication{
		ID:         "0oa1",
		Name:       "my-app",
		Label:      "My Application",
		SignOnMode: "OPENID_CONNECT",
		Settings: OktaAppSettings{
			OAuthClient: &OktaOAuthClient{
				RedirectURIs: []string{"https://app.example.com/callback"},
				GrantTypes:   []string{"authorization_code"},
			},
		},
	}

	// Should be included because signOnMode is OPENID_CONNECT.
	if app.SignOnMode != "OPENID_CONNECT" {
		t.Error("expected OPENID_CONNECT sign-on mode")
	}

	name := app.Label
	if name != "My Application" {
		t.Errorf("expected My Application, got %s", name)
	}

	if len(app.Settings.OAuthClient.RedirectURIs) != 1 {
		t.Fatalf("expected 1 redirect URI, got %d", len(app.Settings.OAuthClient.RedirectURIs))
	}
	if app.Settings.OAuthClient.RedirectURIs[0] != "https://app.example.com/callback" {
		t.Errorf("unexpected redirect URI: %s", app.Settings.OAuthClient.RedirectURIs[0])
	}

	// SAML app should be excluded.
	samlApp := OktaApplication{SignOnMode: "SAML_2_0"}
	if samlApp.SignOnMode == "OPENID_CONNECT" {
		t.Error("SAML app should not be treated as OIDC")
	}
}

func TestOktaImporter_DryRun(t *testing.T) {
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
	export := &OktaExport{
		Users: []OktaUser{
			{
				ID:     "00u1",
				Status: "ACTIVE",
				Profile: OktaProfile{
					Email:     "alice@company.com",
					FirstName: "Alice",
					LastName:  "Smith",
				},
			},
		},
		Groups: []OktaGroup{
			{
				ID:      "00g1",
				Profile: OktaGroupProfile{Name: "Engineering"},
				Users:   []string{"00u1"},
			},
		},
		Applications: []OktaApplication{
			{
				ID:         "0oa1",
				Label:      "My App",
				SignOnMode: "OPENID_CONNECT",
			},
			{
				ID:         "0oa2",
				Label:      "SAML App",
				SignOnMode: "SAML_2_0",
			},
		},
	}

	var buf bytes.Buffer
	importer := NewOktaImporter(export, Config{
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
	if !strings.Contains(output, "alice@company.com") {
		t.Error("expected alice@company.com in output")
	}
	if !strings.Contains(output, "Engineering") {
		t.Error("expected Engineering org in output")
	}
	if !strings.Contains(output, "My App") {
		t.Error("expected My App client in output")
	}
	// SAML app should be excluded.
	if strings.Contains(output, "SAML App") {
		t.Error("expected SAML App to be excluded from dry run")
	}

	if result.UsersCreated != 1 {
		t.Errorf("expected 1 user to create, got %d", result.UsersCreated)
	}
	if result.OrgsCreated != 1 {
		t.Errorf("expected 1 org to create, got %d", result.OrgsCreated)
	}
	if result.ClientsCreated != 1 {
		t.Errorf("expected 1 client to create (OIDC only), got %d", result.ClientsCreated)
	}
}

func TestOktaImporter_LiveImport(t *testing.T) {
	var createdUsers []string
	var createdOrgs []string
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
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"id":    "seki-u1",
				"email": input["email"],
			})
		case r.URL.Path == "/api/v1/orgs" && r.Method == http.MethodPost:
			var input map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&input)
			createdOrgs = append(createdOrgs, input["name"].(string))
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"id":   "seki-o1",
				"slug": input["slug"],
				"name": input["name"],
			})
		case strings.HasSuffix(r.URL.Path, "/members") && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"org_id":  "seki-o1",
				"user_id": "seki-u1",
			})
		case r.URL.Path == "/api/v1/clients" && r.Method == http.MethodPost:
			var input map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&input)
			createdClients = append(createdClients, input["name"].(string))
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"id":   input["id"],
				"name": input["name"],
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	apiClient := client.New(srv.URL, "test-key")
	export := &OktaExport{
		Users: []OktaUser{
			{
				ID:     "00u1",
				Status: "ACTIVE",
				Profile: OktaProfile{
					Email:     "alice@company.com",
					FirstName: "Alice",
					LastName:  "Smith",
				},
			},
		},
		Groups: []OktaGroup{
			{
				ID:      "00g1",
				Profile: OktaGroupProfile{Name: "Engineering"},
				Users:   []string{"00u1"},
			},
		},
		Applications: []OktaApplication{
			{
				ID:         "0oa1",
				Label:      "My App",
				SignOnMode: "OPENID_CONNECT",
				Settings: OktaAppSettings{
					OAuthClient: &OktaOAuthClient{
						RedirectURIs: []string{"https://app.example.com/callback"},
						GrantTypes:   []string{"authorization_code"},
					},
				},
			},
		},
	}

	var buf bytes.Buffer
	importer := NewOktaImporter(export, Config{
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
	if result.ClientsCreated != 1 {
		t.Errorf("expected 1 client created, got %d", result.ClientsCreated)
	}
	if len(createdUsers) != 1 || createdUsers[0] != "alice@company.com" {
		t.Errorf("unexpected created users: %v", createdUsers)
	}
	if len(createdOrgs) != 1 || createdOrgs[0] != "Engineering" {
		t.Errorf("unexpected created orgs: %v", createdOrgs)
	}
	if len(createdClients) != 1 || createdClients[0] != "My App" {
		t.Errorf("unexpected created clients: %v", createdClients)
	}
}

func TestBuildOktaUserMetadata(t *testing.T) {
	u := OktaUser{
		ID:     "00u1abc",
		Status: "ACTIVE",
	}

	meta := buildOktaUserMetadata(u)
	var m map[string]interface{}
	if err := json.Unmarshal(meta, &m); err != nil {
		t.Fatalf("unmarshal metadata: %v", err)
	}

	if m["okta_user_id"] != "00u1abc" {
		t.Errorf("expected 00u1abc, got %v", m["okta_user_id"])
	}
	if m["okta_status"] != "ACTIVE" {
		t.Errorf("expected ACTIVE, got %v", m["okta_status"])
	}
}
