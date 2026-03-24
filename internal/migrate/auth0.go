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

// Auth0User represents a single user record from an Auth0 Management API export.
type Auth0User struct {
	UserID        string          `json:"user_id"`
	Email         string          `json:"email"`
	EmailVerified bool            `json:"email_verified"`
	Name          string          `json:"name"`
	CreatedAt     string          `json:"created_at"`
	Identities    json.RawMessage `json:"identities"`
	AppMetadata   json.RawMessage `json:"app_metadata"`
	UserMetadata  json.RawMessage `json:"user_metadata"`
	PasswordHash  string          `json:"password_hash,omitempty"`
}

// Auth0Client represents a client application from an Auth0 export.
type Auth0Client struct {
	ClientID   string   `json:"client_id"`
	Name       string   `json:"name"`
	AppType    string   `json:"app_type"`
	Callbacks  []string `json:"callbacks"`
	GrantTypes []string `json:"grant_types"`
}

// Auth0Export holds either a user-only export (JSON array) or a combined
// export with a top-level object.
type Auth0Export struct {
	Users   []Auth0User   `json:"users"`
	Clients []Auth0Client `json:"clients"`
}

// ParseAuth0Export reads an Auth0 export file. It handles both a bare JSON array
// of users and an object with "users" and optional "clients" keys.
func ParseAuth0Export(path string) (*Auth0Export, error) {
	f, err := os.Open(path) // #nosec G304 -- intentional: file path from user CLI argument
	if err != nil {
		return nil, fmt.Errorf("open export file: %w", err)
	}
	defer f.Close()
	return parseAuth0ExportReader(f)
}

func parseAuth0ExportReader(r io.Reader) (*Auth0Export, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read export data: %w", err)
	}

	data = []byte(strings.TrimSpace(string(data)))

	// Determine whether top-level is an array (user-only) or an object.
	if len(data) > 0 && data[0] == '[' {
		var users []Auth0User
		if err := json.Unmarshal(data, &users); err != nil {
			return nil, fmt.Errorf("parse Auth0 user array: %w", err)
		}
		return &Auth0Export{Users: users}, nil
	}

	var export Auth0Export
	if err := json.Unmarshal(data, &export); err != nil {
		return nil, fmt.Errorf("parse Auth0 export: %w", err)
	}
	return &export, nil
}

// Auth0Importer imports Auth0 entities into seki.
type Auth0Importer struct {
	export *Auth0Export
	cfg    Config
	output io.Writer
}

// NewAuth0Importer creates an importer from a parsed Auth0 export.
func NewAuth0Importer(export *Auth0Export, cfg Config, output io.Writer) *Auth0Importer {
	return &Auth0Importer{export: export, cfg: cfg, output: output}
}

// Import performs the Auth0 → seki migration.
func (a *Auth0Importer) Import(ctx context.Context) (*MigrationResult, error) {
	if a.cfg.DryRun {
		return a.dryRun(ctx)
	}
	return a.importLive(ctx)
}

func (a *Auth0Importer) dryRun(ctx context.Context) (*MigrationResult, error) {
	reporter := NewReporter()

	for _, u := range a.export.Users {
		email := u.Email
		if email == "" {
			continue
		}
		if _, exists := userExists(ctx, a.cfg.APIClient, email); exists {
			reporter.Add("SKIP", "user", email, fmt.Sprintf("Auth0 ID: %s, already exists", u.UserID))
		} else {
			reporter.Add("CREATE", "user", email, fmt.Sprintf("Auth0 ID: %s", u.UserID))
		}
	}

	for _, c := range a.export.Clients {
		reporter.Add("CREATE", "client", c.Name, fmt.Sprintf("Auth0 Client ID: %s", c.ClientID))
	}

	result := reporter.Print(a.output)
	return result, nil
}

func (a *Auth0Importer) importLive(ctx context.Context) (*MigrationResult, error) {
	result := &MigrationResult{}

	for _, u := range a.export.Users {
		if u.Email == "" {
			result.UsersErrored++
			result.Errors = append(result.Errors, MigrationError{
				Entity: "user",
				ID:     u.UserID,
				Error:  "missing email address",
			})
			continue
		}

		if _, exists := userExists(ctx, a.cfg.APIClient, u.Email); exists {
			result.UsersSkipped++
			if a.cfg.Verbose {
				fmt.Fprintf(a.output, "SKIP user %s (already exists)\n", u.Email)
			}
			continue
		}

		metadata := buildAuth0UserMetadata(u)

		input := client.CreateUserInput{
			Email:       u.Email,
			DisplayName: u.Name,
			Metadata:    metadata,
		}

		_, err := a.cfg.APIClient.CreateUser(ctx, input)
		if err != nil {
			if client.IsConflict(err) {
				result.UsersSkipped++
				if a.cfg.Verbose {
					fmt.Fprintf(a.output, "SKIP user %s (conflict)\n", u.Email)
				}
				continue
			}
			result.UsersErrored++
			result.Errors = append(result.Errors, MigrationError{
				Entity: "user",
				ID:     u.Email,
				Error:  err.Error(),
			})
			continue
		}

		result.UsersCreated++
		if a.cfg.Verbose {
			fmt.Fprintf(a.output, "CREATE user %s\n", u.Email)
		}
	}

	for _, c := range a.export.Clients {
		input := client.CreateClientInput{
			ID:           c.ClientID,
			Name:         c.Name,
			RedirectURIs: c.Callbacks,
			GrantTypes:   c.GrantTypes,
		}

		_, err := a.cfg.APIClient.CreateClient(ctx, input)
		if err != nil {
			if client.IsConflict(err) {
				result.ClientsSkipped++
				continue
			}
			result.Errors = append(result.Errors, MigrationError{
				Entity: "client",
				ID:     c.ClientID,
				Error:  err.Error(),
			})
			continue
		}

		result.ClientsCreated++
		if a.cfg.Verbose {
			fmt.Fprintf(a.output, "CREATE client %s\n", c.Name)
		}
	}

	return result, nil
}

// buildAuth0UserMetadata builds a seki metadata JSON blob preserving the
// original Auth0 user ID and any app/user metadata.
func buildAuth0UserMetadata(u Auth0User) json.RawMessage {
	m := map[string]interface{}{
		"auth0_user_id": u.UserID,
	}

	if len(u.AppMetadata) > 0 && string(u.AppMetadata) != "null" {
		var am interface{}
		if err := json.Unmarshal(u.AppMetadata, &am); err == nil {
			m["auth0_app_metadata"] = am
		}
	}

	if len(u.UserMetadata) > 0 && string(u.UserMetadata) != "null" {
		var um interface{}
		if err := json.Unmarshal(u.UserMetadata, &um); err == nil {
			m["auth0_user_metadata"] = um
		}
	}

	data, _ := json.Marshal(m)
	return data
}
