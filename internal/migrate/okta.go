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

// OktaUser represents a user record from an Okta Management API export.
type OktaUser struct {
	ID      string      `json:"id"`
	Status  string      `json:"status"`
	Profile OktaProfile `json:"profile"`
}

// OktaProfile holds the profile fields of an Okta user.
type OktaProfile struct {
	Login     string `json:"login"`
	Email     string `json:"email"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
}

// OktaGroup represents a group from an Okta export.
type OktaGroup struct {
	ID      string           `json:"id"`
	Profile OktaGroupProfile `json:"profile"`
	Users   []string         `json:"users"`
}

// OktaGroupProfile holds the profile fields of an Okta group.
type OktaGroupProfile struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// OktaApplication represents an application from an Okta export.
type OktaApplication struct {
	ID         string          `json:"id"`
	Name       string          `json:"name"`
	Label      string          `json:"label"`
	SignOnMode string          `json:"signOnMode"`
	Settings   OktaAppSettings `json:"settings"`
}

// OktaAppSettings holds application settings from an Okta export.
type OktaAppSettings struct {
	OAuthClient *OktaOAuthClient `json:"oauthClient,omitempty"`
}

// OktaOAuthClient holds the OAuth client settings for an Okta application.
type OktaOAuthClient struct {
	RedirectURIs []string `json:"redirect_uris"`
	GrantTypes   []string `json:"grant_types"`
}

// OktaExport holds the full Okta export data.
type OktaExport struct {
	Users        []OktaUser        `json:"users"`
	Groups       []OktaGroup       `json:"groups"`
	Applications []OktaApplication `json:"applications"`
}

// ParseOktaExport reads and parses an Okta export file.
func ParseOktaExport(path string) (*OktaExport, error) {
	f, err := os.Open(path) // #nosec G304 -- intentional: file path from user CLI argument
	if err != nil {
		return nil, fmt.Errorf("open export file: %w", err)
	}
	defer f.Close()
	return parseOktaExportReader(f)
}

func parseOktaExportReader(r io.Reader) (*OktaExport, error) {
	var export OktaExport
	if err := json.NewDecoder(r).Decode(&export); err != nil {
		return nil, fmt.Errorf("parse Okta export: %w", err)
	}
	return &export, nil
}

// OktaImporter imports Okta entities into seki.
type OktaImporter struct {
	export *OktaExport
	cfg    Config
	output io.Writer
}

// NewOktaImporter creates an importer from a parsed Okta export.
func NewOktaImporter(export *OktaExport, cfg Config, output io.Writer) *OktaImporter {
	return &OktaImporter{export: export, cfg: cfg, output: output}
}

// Import performs the Okta → seki migration.
func (o *OktaImporter) Import(ctx context.Context) (*MigrationResult, error) {
	if o.cfg.DryRun {
		return o.dryRun(ctx)
	}
	return o.importLive(ctx)
}

func (o *OktaImporter) dryRun(ctx context.Context) (*MigrationResult, error) {
	reporter := NewReporter()

	// Groups → Organizations.
	for _, g := range o.export.Groups {
		reporter.Add("CREATE", "org", g.Profile.Name, fmt.Sprintf("Okta Group ID: %s", g.ID))
	}

	// Users.
	for _, u := range o.export.Users {
		email := oktaUserEmail(u)
		if email == "" {
			continue
		}
		if _, exists := userExists(ctx, o.cfg.APIClient, email); exists {
			reporter.Add("SKIP", "user", email, fmt.Sprintf("Okta ID: %s, already exists", u.ID))
		} else {
			reporter.Add("CREATE", "user", email, fmt.Sprintf("Okta ID: %s", u.ID))
		}
	}

	// Applications → Clients (OIDC only).
	for _, app := range o.export.Applications {
		if app.SignOnMode != "OPENID_CONNECT" {
			continue
		}
		name := app.Label
		if name == "" {
			name = app.Name
		}
		reporter.Add("CREATE", "client", name, fmt.Sprintf("Okta App ID: %s", app.ID))
	}

	result := reporter.Print(o.output)
	return result, nil
}

func (o *OktaImporter) importLive(ctx context.Context) (*MigrationResult, error) {
	result := &MigrationResult{}

	// Build a map of Okta user ID → seki user ID for org membership.
	oktaToSekiUser := make(map[string]string)

	// Groups → Organizations.
	for _, g := range o.export.Groups {
		slug := slugify(g.Profile.Name)
		input := client.CreateOrgInput{
			Slug: slug,
			Name: g.Profile.Name,
			Metadata: mustMarshal(map[string]interface{}{
				"okta_group_id": g.ID,
			}),
		}
		_, err := o.cfg.APIClient.CreateOrg(ctx, input)
		if err != nil {
			if client.IsConflict(err) {
				result.OrgsSkipped++
			} else {
				result.Errors = append(result.Errors, MigrationError{
					Entity: "org",
					ID:     g.Profile.Name,
					Error:  err.Error(),
				})
			}
			continue
		}
		result.OrgsCreated++
		if o.cfg.Verbose {
			fmt.Fprintf(o.output, "CREATE org %s\n", g.Profile.Name)
		}
	}

	// Users.
	for _, u := range o.export.Users {
		email := oktaUserEmail(u)
		if email == "" {
			result.UsersErrored++
			result.Errors = append(result.Errors, MigrationError{
				Entity: "user",
				ID:     u.ID,
				Error:  "missing email address",
			})
			continue
		}

		if existingID, exists := userExists(ctx, o.cfg.APIClient, email); exists {
			result.UsersSkipped++
			oktaToSekiUser[u.ID] = existingID
			if o.cfg.Verbose {
				fmt.Fprintf(o.output, "SKIP user %s (already exists)\n", email)
			}
			continue
		}

		displayName := oktaDisplayName(u)
		metadata := buildOktaUserMetadata(u)

		input := client.CreateUserInput{
			Email:       email,
			DisplayName: displayName,
			Metadata:    metadata,
		}

		created, err := o.cfg.APIClient.CreateUser(ctx, input)
		if err != nil {
			if client.IsConflict(err) {
				result.UsersSkipped++
				if o.cfg.Verbose {
					fmt.Fprintf(o.output, "SKIP user %s (conflict)\n", email)
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

		oktaToSekiUser[u.ID] = created.ID
		result.UsersCreated++
		if o.cfg.Verbose {
			fmt.Fprintf(o.output, "CREATE user %s\n", email)
		}
	}

	// Add group members to organizations.
	for _, g := range o.export.Groups {
		slug := slugify(g.Profile.Name)
		for _, oktaUID := range g.Users {
			sekiUID, ok := oktaToSekiUser[oktaUID]
			if !ok {
				continue
			}
			memberInput := client.AddMemberInput{
				UserID: sekiUID,
			}
			_, err := o.cfg.APIClient.AddMember(ctx, slug, memberInput)
			if err != nil && !client.IsConflict(err) {
				result.Errors = append(result.Errors, MigrationError{
					Entity: "org",
					ID:     fmt.Sprintf("%s/member/%s", g.Profile.Name, oktaUID),
					Error:  err.Error(),
				})
			}
		}
	}

	// Applications → Clients (OIDC only).
	for _, app := range o.export.Applications {
		if app.SignOnMode != "OPENID_CONNECT" {
			continue
		}
		name := app.Label
		if name == "" {
			name = app.Name
		}
		input := client.CreateClientInput{
			ID:   app.ID,
			Name: name,
		}
		if app.Settings.OAuthClient != nil {
			input.RedirectURIs = app.Settings.OAuthClient.RedirectURIs
			input.GrantTypes = app.Settings.OAuthClient.GrantTypes
		}

		_, err := o.cfg.APIClient.CreateClient(ctx, input)
		if err != nil {
			if client.IsConflict(err) {
				result.ClientsSkipped++
				continue
			}
			result.Errors = append(result.Errors, MigrationError{
				Entity: "client",
				ID:     app.ID,
				Error:  err.Error(),
			})
			continue
		}
		result.ClientsCreated++
		if o.cfg.Verbose {
			fmt.Fprintf(o.output, "CREATE client %s\n", name)
		}
	}

	return result, nil
}

// oktaUserEmail returns the email for an Okta user.
func oktaUserEmail(u OktaUser) string {
	if u.Profile.Email != "" {
		return u.Profile.Email
	}
	if strings.Contains(u.Profile.Login, "@") {
		return u.Profile.Login
	}
	return ""
}

// oktaDisplayName builds a display name from first/last name.
func oktaDisplayName(u OktaUser) string {
	parts := strings.TrimSpace(u.Profile.FirstName + " " + u.Profile.LastName)
	if parts != "" {
		return parts
	}
	return u.Profile.Login
}

// oktaStatusDisabled returns true if the Okta user status means the user
// should be disabled in seki.
func oktaStatusDisabled(status string) bool {
	switch status {
	case "ACTIVE", "STAGED":
		return false
	default:
		return true
	}
}

// buildOktaUserMetadata builds a seki metadata JSON blob preserving the
// original Okta user ID and status.
func buildOktaUserMetadata(u OktaUser) json.RawMessage {
	m := map[string]interface{}{
		"okta_user_id": u.ID,
		"okta_status":  u.Status,
	}
	data, _ := json.Marshal(m)
	return data
}
