package migrate

import (
	"fmt"
	"io"
	"strings"
)

// DryRunAction describes a planned migration action.
type DryRunAction struct {
	Verb   string // "CREATE" or "SKIP"
	Entity string // "user", "client", "role", "org"
	Name   string // display identifier (e.g. email, client name)
	Detail string // extra info (e.g. "Auth0 ID: auth0|123")
}

// Reporter collects dry-run actions and prints them.
type Reporter struct {
	actions []DryRunAction
}

// NewReporter creates a new Reporter.
func NewReporter() *Reporter {
	return &Reporter{}
}

// Add records a planned action.
func (r *Reporter) Add(verb, entity, name, detail string) {
	r.actions = append(r.actions, DryRunAction{
		Verb:   verb,
		Entity: entity,
		Name:   name,
		Detail: detail,
	})
}

// Print writes the dry-run report to w and returns a MigrationResult
// summarising what would happen.
func (r *Reporter) Print(w io.Writer) *MigrationResult {
	fmt.Fprintln(w, "DRY RUN — no changes will be made")
	fmt.Fprintln(w)

	result := &MigrationResult{}

	groups := []string{"user", "client", "role", "org"}
	labels := map[string]string{
		"user":   "Users",
		"client": "Clients",
		"role":   "Roles",
		"org":    "Organizations",
	}

	for _, entity := range groups {
		var items []DryRunAction
		for _, a := range r.actions {
			if a.Entity == entity {
				items = append(items, a)
			}
		}
		if len(items) == 0 {
			continue
		}

		fmt.Fprintf(w, "%s:\n", labels[entity])
		for _, a := range items {
			prefix := "+"
			if a.Verb == "SKIP" {
				prefix = "~"
			}

			line := fmt.Sprintf("  %s %-6s %s", prefix, a.Verb, a.Name)
			if a.Detail != "" {
				line += fmt.Sprintf(" (%s)", a.Detail)
			}
			fmt.Fprintln(w, line)

			switch {
			case entity == "user" && a.Verb == "CREATE":
				result.UsersCreated++
			case entity == "user" && a.Verb == "SKIP":
				result.UsersSkipped++
			case entity == "client" && a.Verb == "CREATE":
				result.ClientsCreated++
			case entity == "client" && a.Verb == "SKIP":
				result.ClientsSkipped++
			case entity == "role" && a.Verb == "CREATE":
				result.RolesCreated++
			case entity == "role" && a.Verb == "SKIP":
				result.RolesSkipped++
			case entity == "org" && a.Verb == "CREATE":
				result.OrgsCreated++
			case entity == "org" && a.Verb == "SKIP":
				result.OrgsSkipped++
			}
		}
		fmt.Fprintln(w)
	}

	// Print summary line.
	var parts []string
	if result.UsersCreated > 0 || result.UsersSkipped > 0 {
		parts = append(parts, fmt.Sprintf("%d users to create, %d to skip", result.UsersCreated, result.UsersSkipped))
	}
	if result.ClientsCreated > 0 || result.ClientsSkipped > 0 {
		parts = append(parts, fmt.Sprintf("%d clients to create, %d to skip", result.ClientsCreated, result.ClientsSkipped))
	}
	if result.RolesCreated > 0 || result.RolesSkipped > 0 {
		parts = append(parts, fmt.Sprintf("%d roles to create, %d to skip", result.RolesCreated, result.RolesSkipped))
	}
	if result.OrgsCreated > 0 || result.OrgsSkipped > 0 {
		parts = append(parts, fmt.Sprintf("%d orgs to create, %d to skip", result.OrgsCreated, result.OrgsSkipped))
	}
	if len(parts) > 0 {
		fmt.Fprintf(w, "Summary: %s\n", strings.Join(parts, ", "))
	}

	return result
}
