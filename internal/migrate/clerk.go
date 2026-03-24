package migrate

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/entoten/seki/pkg/client"
)

// ClerkUser represents a user record from the Clerk Backend API export.
type ClerkUser struct {
	ID               string                `json:"id"`
	EmailAddresses   []ClerkEmailAddress   `json:"email_addresses"`
	FirstName        string                `json:"first_name"`
	LastName         string                `json:"last_name"`
	CreatedAt        int64                 `json:"created_at"`
	ExternalAccounts []ClerkExternalAccount `json:"external_accounts"`
}

// ClerkEmailAddress holds an email address and its verification status.
type ClerkEmailAddress struct {
	EmailAddress string             `json:"email_address"`
	Verification *ClerkVerification `json:"verification,omitempty"`
}

// ClerkVerification holds the verification status of an email address.
type ClerkVerification struct {
	Status string `json:"status"`
}

// ClerkExternalAccount holds an external account linked to a Clerk user.
type ClerkExternalAccount struct {
	Provider     string `json:"provider"`
	EmailAddress string `json:"email_address"`
}

// ClerkOrganization represents an organization from a Clerk export.
type ClerkOrganization struct {
	ID      string        `json:"id"`
	Name    string        `json:"name"`
	Slug    string        `json:"slug"`
	Members []ClerkMember `json:"members"`
}

// ClerkMember represents a member of a Clerk organization.
type ClerkMember struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
}

// ClerkExport holds the full Clerk export data.
type ClerkExport struct {
	Users         []ClerkUser         `json:"users"`
	Organizations []ClerkOrganization `json:"organizations"`
}

// ParseClerkExport reads and parses a Clerk export file.
func ParseClerkExport(path string) (*ClerkExport, error) {
	f, err := os.Open(path) // #nosec G304 -- intentional: file path from user CLI argument
	if err != nil {
		return nil, fmt.Errorf("open export file: %w", err)
	}
	defer f.Close()
	return parseClerkExportReader(f)
}

func parseClerkExportReader(r io.Reader) (*ClerkExport, error) {
	var export ClerkExport
	if err := json.NewDecoder(r).Decode(&export); err != nil {
		return nil, fmt.Errorf("parse Clerk export: %w", err)
	}
	return &export, nil
}

// ClerkImporter imports Clerk entities into seki.
type ClerkImporter struct {
	export *ClerkExport
	cfg    Config
	output io.Writer
}

// NewClerkImporter creates an importer from a parsed Clerk export.
func NewClerkImporter(export *ClerkExport, cfg Config, output io.Writer) *ClerkImporter {
	return &ClerkImporter{export: export, cfg: cfg, output: output}
}

// Import performs the Clerk → seki migration.
func (c *ClerkImporter) Import(ctx context.Context) (*MigrationResult, error) {
	if c.cfg.DryRun {
		return c.dryRun(ctx)
	}
	return c.importLive(ctx)
}

func (c *ClerkImporter) dryRun(ctx context.Context) (*MigrationResult, error) {
	reporter := NewReporter()

	// Organizations.
	for _, org := range c.export.Organizations {
		reporter.Add("CREATE", "org", org.Name, fmt.Sprintf("Clerk Org ID: %s, slug: %s", org.ID, org.Slug))
	}

	// Users.
	for _, u := range c.export.Users {
		email := clerkUserEmail(u)
		if email == "" {
			continue
		}
		if _, exists := userExists(ctx, c.cfg.APIClient, email); exists {
			reporter.Add("SKIP", "user", email, fmt.Sprintf("Clerk ID: %s, already exists", u.ID))
		} else {
			reporter.Add("CREATE", "user", email, fmt.Sprintf("Clerk ID: %s", u.ID))
		}
	}

	result := reporter.Print(c.output)
	return result, nil
}

func (c *ClerkImporter) importLive(ctx context.Context) (*MigrationResult, error) {
	result := &MigrationResult{}

	// Build a map of Clerk user ID → seki user ID for org membership.
	clerkToSekiUser := make(map[string]string)

	// Organizations.
	for _, org := range c.export.Organizations {
		slug := org.Slug
		if slug == "" {
			slug = slugify(org.Name)
		}
		input := client.CreateOrgInput{
			Slug: slug,
			Name: org.Name,
			Metadata: mustMarshal(map[string]interface{}{
				"clerk_org_id": org.ID,
			}),
		}
		_, err := c.cfg.APIClient.CreateOrg(ctx, input)
		if err != nil {
			if client.IsConflict(err) {
				result.OrgsSkipped++
			} else {
				result.Errors = append(result.Errors, MigrationError{
					Entity: "org",
					ID:     org.Name,
					Error:  err.Error(),
				})
			}
			continue
		}
		result.OrgsCreated++
		if c.cfg.Verbose {
			fmt.Fprintf(c.output, "CREATE org %s\n", org.Name)
		}
	}

	// Users.
	for _, u := range c.export.Users {
		email := clerkUserEmail(u)
		if email == "" {
			result.UsersErrored++
			result.Errors = append(result.Errors, MigrationError{
				Entity: "user",
				ID:     u.ID,
				Error:  "missing email address",
			})
			continue
		}

		if existingID, exists := userExists(ctx, c.cfg.APIClient, email); exists {
			result.UsersSkipped++
			clerkToSekiUser[u.ID] = existingID
			if c.cfg.Verbose {
				fmt.Fprintf(c.output, "SKIP user %s (already exists)\n", email)
			}
			continue
		}

		displayName := clerkDisplayName(u)
		metadata := buildClerkUserMetadata(u)

		input := client.CreateUserInput{
			Email:       email,
			DisplayName: displayName,
			Metadata:    metadata,
		}

		created, err := c.cfg.APIClient.CreateUser(ctx, input)
		if err != nil {
			if client.IsConflict(err) {
				result.UsersSkipped++
				if c.cfg.Verbose {
					fmt.Fprintf(c.output, "SKIP user %s (conflict)\n", email)
				}
				continue
			}
			result.UsersErrored++
			result.Errors = append(result.Errors, MigrationError{
				Entity: "user",
				ID:     email,
				Error:  err.Error(),
			})
			continue
		}

		clerkToSekiUser[u.ID] = created.ID
		result.UsersCreated++
		if c.cfg.Verbose {
			fmt.Fprintf(c.output, "CREATE user %s\n", email)
		}
	}

	// Add org members with roles.
	for _, org := range c.export.Organizations {
		slug := org.Slug
		if slug == "" {
			slug = slugify(org.Name)
		}
		for _, m := range org.Members {
			sekiUID, ok := clerkToSekiUser[m.UserID]
			if !ok {
				continue
			}
			memberInput := client.AddMemberInput{
				UserID: sekiUID,
				Role:   m.Role,
			}
			_, err := c.cfg.APIClient.AddMember(ctx, slug, memberInput)
			if err != nil && !client.IsConflict(err) {
				result.Errors = append(result.Errors, MigrationError{
					Entity: "org",
					ID:     fmt.Sprintf("%s/member/%s", org.Name, m.UserID),
					Error:  err.Error(),
				})
			}
		}
	}

	return result, nil
}

// clerkUserEmail returns the primary email for a Clerk user.
func clerkUserEmail(u ClerkUser) string {
	if len(u.EmailAddresses) > 0 {
		return u.EmailAddresses[0].EmailAddress
	}
	return ""
}

// clerkEmailVerified reports whether the primary email is verified.
func clerkEmailVerified(u ClerkUser) bool {
	if len(u.EmailAddresses) > 0 && u.EmailAddresses[0].Verification != nil {
		return u.EmailAddresses[0].Verification.Status == "verified"
	}
	return false
}

// clerkDisplayName builds a display name from first/last name.
func clerkDisplayName(u ClerkUser) string {
	parts := strings.TrimSpace(u.FirstName + " " + u.LastName)
	if parts != "" {
		return parts
	}
	return clerkUserEmail(u)
}

// buildClerkUserMetadata builds a seki metadata JSON blob preserving the
// original Clerk user ID and external accounts.
func buildClerkUserMetadata(u ClerkUser) json.RawMessage {
	m := map[string]interface{}{
		"clerk_user_id":    u.ID,
		"email_verified":   clerkEmailVerified(u),
	}
	if len(u.ExternalAccounts) > 0 {
		accounts := make([]map[string]string, len(u.ExternalAccounts))
		for i, ea := range u.ExternalAccounts {
			accounts[i] = map[string]string{
				"provider":      ea.Provider,
				"email_address": ea.EmailAddress,
			}
		}
		m["clerk_external_accounts"] = accounts
	}
	data, _ := json.Marshal(m)
	return data
}
