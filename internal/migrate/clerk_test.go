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

func TestParseClerkExport(t *testing.T) {
	input := `{
		"users": [
			{
				"id": "user_2abc",
				"email_addresses": [
					{"email_address": "alice@company.com", "verification": {"status": "verified"}}
				],
				"first_name": "Alice",
				"last_name": "Smith",
				"created_at": 1700000000000,
				"external_accounts": [
					{"provider": "oauth_google", "email_address": "alice@gmail.com"}
				]
			},
			{
				"id": "user_2def",
				"email_addresses": [
					{"email_address": "bob@company.com", "verification": {"status": "unverified"}}
				],
				"first_name": "Bob",
				"last_name": "Jones"
			}
		],
		"organizations": [
			{
				"id": "org_2abc",
				"name": "Acme Corp",
				"slug": "acme-corp",
				"members": [
					{"user_id": "user_2abc", "role": "admin"},
					{"user_id": "user_2def", "role": "member"}
				]
			}
		]
	}`

	export, err := parseClerkExportReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(export.Users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(export.Users))
	}
	if export.Users[0].ID != "user_2abc" {
		t.Errorf("expected user_2abc, got %s", export.Users[0].ID)
	}
	if export.Users[0].EmailAddresses[0].EmailAddress != "alice@company.com" {
		t.Errorf("expected alice@company.com, got %s", export.Users[0].EmailAddresses[0].EmailAddress)
	}
	if export.Users[0].FirstName != "Alice" {
		t.Errorf("expected Alice, got %s", export.Users[0].FirstName)
	}
	if len(export.Users[0].ExternalAccounts) != 1 {
		t.Fatalf("expected 1 external account, got %d", len(export.Users[0].ExternalAccounts))
	}
	if export.Users[0].ExternalAccounts[0].Provider != "oauth_google" {
		t.Errorf("expected oauth_google, got %s", export.Users[0].ExternalAccounts[0].Provider)
	}

	if len(export.Organizations) != 1 {
		t.Fatalf("expected 1 organization, got %d", len(export.Organizations))
	}
	if export.Organizations[0].Slug != "acme-corp" {
		t.Errorf("expected acme-corp, got %s", export.Organizations[0].Slug)
	}
	if len(export.Organizations[0].Members) != 2 {
		t.Fatalf("expected 2 members, got %d", len(export.Organizations[0].Members))
	}
}

func TestParseClerkExport_InvalidJSON(t *testing.T) {
	_, err := parseClerkExportReader(strings.NewReader("not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestClerkUserMapping(t *testing.T) {
	u := ClerkUser{
		ID: "user_2abc",
		EmailAddresses: []ClerkEmailAddress{
			{EmailAddress: "alice@company.com", Verification: &ClerkVerification{Status: "verified"}},
		},
		FirstName: "Alice",
		LastName:  "Smith",
	}

	email := clerkUserEmail(u)
	if email != "alice@company.com" {
		t.Errorf("expected alice@company.com, got %s", email)
	}

	display := clerkDisplayName(u)
	if display != "Alice Smith" {
		t.Errorf("expected Alice Smith, got %s", display)
	}

	// Test empty email addresses.
	u2 := ClerkUser{ID: "user_empty"}
	if clerkUserEmail(u2) != "" {
		t.Errorf("expected empty email, got %s", clerkUserEmail(u2))
	}

	// Test display name fallback to email.
	u3 := ClerkUser{
		EmailAddresses: []ClerkEmailAddress{
			{EmailAddress: "fallback@example.com"},
		},
	}
	if clerkDisplayName(u3) != "fallback@example.com" {
		t.Errorf("expected fallback@example.com, got %s", clerkDisplayName(u3))
	}
}

func TestClerkOrgMapping(t *testing.T) {
	org := ClerkOrganization{
		ID:   "org_2abc",
		Name: "Acme Corp",
		Slug: "acme-corp",
		Members: []ClerkMember{
			{UserID: "user_2abc", Role: "admin"},
			{UserID: "user_2def", Role: "member"},
		},
	}

	// Clerk orgs keep their slug.
	if org.Slug != "acme-corp" {
		t.Errorf("expected acme-corp slug, got %s", org.Slug)
	}
	if len(org.Members) != 2 {
		t.Errorf("expected 2 members, got %d", len(org.Members))
	}
	if org.Members[0].Role != "admin" {
		t.Errorf("expected admin role, got %s", org.Members[0].Role)
	}
	if org.Members[1].Role != "member" {
		t.Errorf("expected member role, got %s", org.Members[1].Role)
	}
}

func TestClerkMemberMapping(t *testing.T) {
	members := []ClerkMember{
		{UserID: "user_2abc", Role: "admin"},
		{UserID: "user_2def", Role: "member"},
		{UserID: "user_2ghi", Role: ""},
	}

	if members[0].UserID != "user_2abc" {
		t.Errorf("expected user_2abc, got %s", members[0].UserID)
	}
	if members[0].Role != "admin" {
		t.Errorf("expected admin, got %s", members[0].Role)
	}
	if members[2].Role != "" {
		t.Errorf("expected empty role, got %s", members[2].Role)
	}
}

func TestClerkEmailVerification(t *testing.T) {
	tests := []struct {
		name     string
		user     ClerkUser
		expected bool
	}{
		{
			name: "verified",
			user: ClerkUser{
				EmailAddresses: []ClerkEmailAddress{
					{EmailAddress: "a@b.com", Verification: &ClerkVerification{Status: "verified"}},
				},
			},
			expected: true,
		},
		{
			name: "unverified",
			user: ClerkUser{
				EmailAddresses: []ClerkEmailAddress{
					{EmailAddress: "a@b.com", Verification: &ClerkVerification{Status: "unverified"}},
				},
			},
			expected: false,
		},
		{
			name: "no verification field",
			user: ClerkUser{
				EmailAddresses: []ClerkEmailAddress{
					{EmailAddress: "a@b.com"},
				},
			},
			expected: false,
		},
		{
			name:     "no email addresses",
			user:     ClerkUser{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := clerkEmailVerified(tt.user)
			if got != tt.expected {
				t.Errorf("clerkEmailVerified() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestClerkImporter_DryRun(t *testing.T) {
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
	export := &ClerkExport{
		Users: []ClerkUser{
			{
				ID: "user_2abc",
				EmailAddresses: []ClerkEmailAddress{
					{EmailAddress: "alice@company.com", Verification: &ClerkVerification{Status: "verified"}},
				},
				FirstName: "Alice",
				LastName:  "Smith",
			},
		},
		Organizations: []ClerkOrganization{
			{
				ID:   "org_2abc",
				Name: "Acme Corp",
				Slug: "acme-corp",
				Members: []ClerkMember{
					{UserID: "user_2abc", Role: "admin"},
				},
			},
		},
	}

	var buf bytes.Buffer
	importer := NewClerkImporter(export, Config{
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
	if !strings.Contains(output, "Acme Corp") {
		t.Error("expected Acme Corp org in output")
	}

	if result.UsersCreated != 1 {
		t.Errorf("expected 1 user to create, got %d", result.UsersCreated)
	}
	if result.OrgsCreated != 1 {
		t.Errorf("expected 1 org to create, got %d", result.OrgsCreated)
	}
}

func TestClerkImporter_LiveImport(t *testing.T) {
	var createdUsers []string
	var createdOrgs []string
	var addedMembers []map[string]string

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
			var input map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&input)
			addedMembers = append(addedMembers, map[string]string{
				"user_id": input["user_id"].(string),
				"role":    stringOrEmpty(input["role"]),
			})
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"org_id":  "seki-o1",
				"user_id": input["user_id"],
				"role":    input["role"],
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	apiClient := client.New(srv.URL, "test-key")
	export := &ClerkExport{
		Users: []ClerkUser{
			{
				ID: "user_2abc",
				EmailAddresses: []ClerkEmailAddress{
					{EmailAddress: "alice@company.com", Verification: &ClerkVerification{Status: "verified"}},
				},
				FirstName: "Alice",
				LastName:  "Smith",
			},
		},
		Organizations: []ClerkOrganization{
			{
				ID:   "org_2abc",
				Name: "Acme Corp",
				Slug: "acme-corp",
				Members: []ClerkMember{
					{UserID: "user_2abc", Role: "admin"},
				},
			},
		},
	}

	var buf bytes.Buffer
	importer := NewClerkImporter(export, Config{
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
	if len(createdUsers) != 1 || createdUsers[0] != "alice@company.com" {
		t.Errorf("unexpected created users: %v", createdUsers)
	}
	if len(createdOrgs) != 1 || createdOrgs[0] != "Acme Corp" {
		t.Errorf("unexpected created orgs: %v", createdOrgs)
	}
	if len(addedMembers) != 1 {
		t.Fatalf("expected 1 member added, got %d", len(addedMembers))
	}
	if addedMembers[0]["user_id"] != "seki-u1" {
		t.Errorf("expected seki-u1, got %s", addedMembers[0]["user_id"])
	}
	if addedMembers[0]["role"] != "admin" {
		t.Errorf("expected admin role, got %s", addedMembers[0]["role"])
	}
}

func TestBuildClerkUserMetadata(t *testing.T) {
	u := ClerkUser{
		ID: "user_2abc",
		EmailAddresses: []ClerkEmailAddress{
			{EmailAddress: "alice@company.com", Verification: &ClerkVerification{Status: "verified"}},
		},
		ExternalAccounts: []ClerkExternalAccount{
			{Provider: "oauth_google", EmailAddress: "alice@gmail.com"},
		},
	}

	meta := buildClerkUserMetadata(u)
	var m map[string]interface{}
	if err := json.Unmarshal(meta, &m); err != nil {
		t.Fatalf("unmarshal metadata: %v", err)
	}

	if m["clerk_user_id"] != "user_2abc" {
		t.Errorf("expected user_2abc, got %v", m["clerk_user_id"])
	}
	if m["email_verified"] != true {
		t.Errorf("expected email_verified=true, got %v", m["email_verified"])
	}
	accounts, ok := m["clerk_external_accounts"].([]interface{})
	if !ok {
		t.Fatal("expected clerk_external_accounts to be an array")
	}
	if len(accounts) != 1 {
		t.Fatalf("expected 1 external account, got %d", len(accounts))
	}
	acct := accounts[0].(map[string]interface{})
	if acct["provider"] != "oauth_google" {
		t.Errorf("expected oauth_google, got %v", acct["provider"])
	}
}

// stringOrEmpty safely extracts a string from an interface{}, returning "" if nil.
func stringOrEmpty(v interface{}) string {
	if v == nil {
		return ""
	}
	s, _ := v.(string)
	return s
}
