// Package migrate provides importers for migrating users, clients, and roles
// from external identity providers (Auth0, Keycloak) into seki.
package migrate

import (
	"context"
	"fmt"
	"strings"

	"github.com/entoten/seki/pkg/client"
)

// Config holds migration settings shared by all importers.
type Config struct {
	APIClient     *client.Client
	DryRun        bool
	SkipPasswords bool
	Verbose       bool
}

// MigrationResult tracks the outcome of a migration run.
type MigrationResult struct {
	UsersCreated   int
	UsersSkipped   int
	UsersErrored   int
	ClientsCreated int
	ClientsSkipped int
	RolesCreated   int
	RolesSkipped   int
	OrgsCreated    int
	OrgsSkipped    int
	Errors         []MigrationError
}

// MigrationError describes a single entity that failed to import.
type MigrationError struct {
	Entity string // "user", "client", "role", "org"
	ID     string // identifier from the source system
	Error  string
}

// Summary returns a human-readable summary of the migration result.
func (r *MigrationResult) Summary() string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("Users:   %d created, %d skipped, %d errors\n", r.UsersCreated, r.UsersSkipped, r.UsersErrored))
	b.WriteString(fmt.Sprintf("Clients: %d created, %d skipped\n", r.ClientsCreated, r.ClientsSkipped))
	b.WriteString(fmt.Sprintf("Roles:   %d created, %d skipped\n", r.RolesCreated, r.RolesSkipped))
	b.WriteString(fmt.Sprintf("Orgs:    %d created, %d skipped\n", r.OrgsCreated, r.OrgsSkipped))
	if len(r.Errors) > 0 {
		b.WriteString(fmt.Sprintf("\n%d error(s):\n", len(r.Errors)))
		for _, e := range r.Errors {
			b.WriteString(fmt.Sprintf("  [%s] %s: %s\n", e.Entity, e.ID, e.Error))
		}
	}
	return b.String()
}

// Importer is the interface implemented by source-specific importers.
type Importer interface {
	// Import runs the migration, creating entities via the API or reporting
	// what would happen in dry-run mode.
	Import(ctx context.Context) (*MigrationResult, error)
}

// userExists checks whether a user with the given email already exists by
// listing users and scanning for a match. Returns the user ID if found.
func userExists(ctx context.Context, c *client.Client, email string) (string, bool) {
	cursor := ""
	for {
		result, err := c.ListUsers(ctx, client.ListOptions{Cursor: cursor, Limit: 100})
		if err != nil {
			return "", false
		}
		for _, u := range result.Data {
			if strings.EqualFold(u.Email, email) {
				return u.ID, true
			}
		}
		if result.NextCursor == "" {
			break
		}
		cursor = result.NextCursor
	}
	return "", false
}
