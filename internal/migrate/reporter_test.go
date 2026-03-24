package migrate

import (
	"bytes"
	"strings"
	"testing"
)

func TestReporter(t *testing.T) {
	r := NewReporter()

	r.Add("CREATE", "user", "alice@example.com", "Auth0 ID: auth0|123")
	r.Add("SKIP", "user", "bob@example.com", "already exists")
	r.Add("CREATE", "client", "my-app", "")
	r.Add("CREATE", "role", "admin", "org: acme")
	r.Add("SKIP", "org", "acme", "already exists")
	r.Add("CREATE", "org", "beta", "")

	var buf bytes.Buffer
	result := r.Print(&buf)

	output := buf.String()

	// Verify header.
	if !strings.Contains(output, "DRY RUN") {
		t.Error("expected DRY RUN header")
	}

	// Verify counts.
	if result.UsersCreated != 1 {
		t.Errorf("UsersCreated = %d, want 1", result.UsersCreated)
	}
	if result.UsersSkipped != 1 {
		t.Errorf("UsersSkipped = %d, want 1", result.UsersSkipped)
	}
	if result.ClientsCreated != 1 {
		t.Errorf("ClientsCreated = %d, want 1", result.ClientsCreated)
	}
	if result.RolesCreated != 1 {
		t.Errorf("RolesCreated = %d, want 1", result.RolesCreated)
	}
	if result.OrgsCreated != 1 {
		t.Errorf("OrgsCreated = %d, want 1", result.OrgsCreated)
	}
	if result.OrgsSkipped != 1 {
		t.Errorf("OrgsSkipped = %d, want 1", result.OrgsSkipped)
	}
}

func TestMigrationResult_Summary(t *testing.T) {
	r := &MigrationResult{
		UsersCreated:   3,
		UsersSkipped:   1,
		UsersErrored:   1,
		ClientsCreated: 2,
		ClientsSkipped: 0,
		RolesCreated:   1,
		RolesSkipped:   0,
		OrgsCreated:    1,
		OrgsSkipped:    0,
		Errors: []MigrationError{
			{Entity: "user", ID: "u1", Error: "duplicate email"},
		},
	}

	summary := r.Summary()

	if !strings.Contains(summary, "3 created") {
		t.Error("expected users created count in summary")
	}
	if !strings.Contains(summary, "1 error") {
		t.Error("expected error count in summary")
	}
	if !strings.Contains(summary, "duplicate email") {
		t.Error("expected error detail in summary")
	}
}

func TestReporter_Empty(t *testing.T) {
	r := NewReporter()
	var buf bytes.Buffer
	result := r.Print(&buf)

	if result.UsersCreated != 0 {
		t.Errorf("expected 0, got %d", result.UsersCreated)
	}
}
