package migrate

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/entoten/seki/pkg/client"
)

// KeycloakRealmExport represents a Keycloak realm export.
type KeycloakRealmExport struct {
	Realm   string           `json:"realm"`
	Users   []KeycloakUser   `json:"users"`
	Clients []KeycloakClient `json:"clients"`
	Roles   *KeycloakRoles   `json:"roles"`
	Groups  []KeycloakGroup  `json:"groups"`
}

// KeycloakUser represents a user in a Keycloak export.
type KeycloakUser struct {
	ID            string               `json:"id"`
	Username      string               `json:"username"`
	Email         string               `json:"email"`
	EmailVerified bool                 `json:"emailVerified"`
	Enabled       bool                 `json:"enabled"`
	FirstName     string               `json:"firstName"`
	LastName      string               `json:"lastName"`
	Credentials   []KeycloakCredential `json:"credentials"`
	RealmRoles    []string             `json:"realmRoles"`
	Groups        []string             `json:"groups"`
}

// KeycloakCredential represents a credential in a Keycloak export.
type KeycloakCredential struct {
	Type      string `json:"type"`
	Value     string `json:"value"`
	Algorithm string `json:"algorithm"`
}

// KeycloakClient represents a client in a Keycloak export.
type KeycloakClient struct {
	ClientID     string   `json:"clientId"`
	Name         string   `json:"name"`
	Enabled      bool     `json:"enabled"`
	PublicClient bool     `json:"publicClient"`
	RedirectURIs []string `json:"redirectUris"`
	Protocol     string   `json:"protocol"`
}

// KeycloakRoles holds realm-level and client-level roles.
type KeycloakRoles struct {
	Realm []KeycloakRole `json:"realm"`
}

// KeycloakRole represents a single role definition.
type KeycloakRole struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Composite   bool   `json:"composite"`
}

// KeycloakGroup represents a group in a Keycloak export.
type KeycloakGroup struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Path      string          `json:"path"`
	SubGroups []KeycloakGroup `json:"subGroups"`
}

// ParseKeycloakExport reads and parses a Keycloak realm export file.
func ParseKeycloakExport(path string) (*KeycloakRealmExport, error) {
	f, err := os.Open(path) // #nosec G304 -- intentional: file path from user CLI argument
	if err != nil {
		return nil, fmt.Errorf("open export file: %w", err)
	}
	defer f.Close()
	return parseKeycloakExportReader(f)
}

func parseKeycloakExportReader(r io.Reader) (*KeycloakRealmExport, error) {
	var export KeycloakRealmExport
	if err := json.NewDecoder(r).Decode(&export); err != nil {
		return nil, fmt.Errorf("parse Keycloak export: %w", err)
	}
	return &export, nil
}

// KeycloakImporter imports Keycloak realm entities into seki.
type KeycloakImporter struct {
	export *KeycloakRealmExport
	cfg    Config
	output io.Writer
}

// NewKeycloakImporter creates an importer from a parsed Keycloak export.
func NewKeycloakImporter(export *KeycloakRealmExport, cfg Config, output io.Writer) *KeycloakImporter {
	return &KeycloakImporter{export: export, cfg: cfg, output: output}
}

// Import performs the Keycloak → seki migration.
func (k *KeycloakImporter) Import(ctx context.Context) (*MigrationResult, error) {
	if k.cfg.DryRun {
		return k.dryRun(ctx)
	}
	return k.importLive(ctx)
}

func (k *KeycloakImporter) dryRun(ctx context.Context) (*MigrationResult, error) {
	reporter := NewReporter()

	// Groups → Organizations.
	for _, g := range k.export.Groups {
		reporter.Add("CREATE", "org", g.Name, fmt.Sprintf("Keycloak Group ID: %s", g.ID))
	}

	// Realm roles.
	if k.export.Roles != nil {
		for _, r := range k.export.Roles.Realm {
			if isKeycloakDefaultRole(r.Name) {
				continue
			}
			reporter.Add("CREATE", "role", r.Name, fmt.Sprintf("Keycloak Role ID: %s", r.ID))
		}
	}

	// Users.
	for _, u := range k.export.Users {
		email := keycloakUserEmail(u)
		if email == "" {
			continue
		}
		if _, exists := userExists(ctx, k.cfg.APIClient, email); exists {
			reporter.Add("SKIP", "user", email, fmt.Sprintf("Keycloak ID: %s, already exists", u.ID))
		} else {
			reporter.Add("CREATE", "user", email, fmt.Sprintf("Keycloak ID: %s", u.ID))
		}
	}

	// Clients.
	for _, c := range k.export.Clients {
		if !c.Enabled || c.Protocol != "openid-connect" {
			continue
		}
		name := c.Name
		if name == "" {
			name = c.ClientID
		}
		reporter.Add("CREATE", "client", name, fmt.Sprintf("Keycloak Client ID: %s", c.ClientID))
	}

	result := reporter.Print(k.output)
	return result, nil
}

func (k *KeycloakImporter) importLive(ctx context.Context) (*MigrationResult, error) {
	result := &MigrationResult{}

	// Groups → Organizations.
	for _, g := range k.export.Groups {
		slug := slugify(g.Name)
		input := client.CreateOrgInput{
			Slug: slug,
			Name: g.Name,
			Metadata: mustMarshal(map[string]interface{}{
				"keycloak_group_id": g.ID,
			}),
		}
		_, err := k.cfg.APIClient.CreateOrg(ctx, input)
		if err != nil {
			if client.IsConflict(err) {
				result.OrgsSkipped++
				continue
			}
			result.Errors = append(result.Errors, MigrationError{
				Entity: "org",
				ID:     g.Name,
				Error:  err.Error(),
			})
			continue
		}
		result.OrgsCreated++
		if k.cfg.Verbose {
			fmt.Fprintf(k.output, "CREATE org %s\n", g.Name)
		}
	}

	// Realm roles — require an org, so we skip if no groups exist.
	// For simplicity, attach realm roles to the first organization if any.
	if k.export.Roles != nil && len(k.export.Groups) > 0 {
		orgSlug := slugify(k.export.Groups[0].Name)
		for _, r := range k.export.Roles.Realm {
			if isKeycloakDefaultRole(r.Name) {
				continue
			}
			input := client.CreateRoleInput{
				Name: r.Name,
			}
			_, err := k.cfg.APIClient.CreateRole(ctx, orgSlug, input)
			if err != nil {
				if client.IsConflict(err) {
					result.RolesSkipped++
					continue
				}
				result.Errors = append(result.Errors, MigrationError{
					Entity: "role",
					ID:     r.Name,
					Error:  err.Error(),
				})
				continue
			}
			result.RolesCreated++
			if k.cfg.Verbose {
				fmt.Fprintf(k.output, "CREATE role %s\n", r.Name)
			}
		}
	}

	// Users.
	for _, u := range k.export.Users {
		email := keycloakUserEmail(u)
		if email == "" {
			result.UsersErrored++
			result.Errors = append(result.Errors, MigrationError{
				Entity: "user",
				ID:     u.ID,
				Error:  "missing email address",
			})
			continue
		}

		if _, exists := userExists(ctx, k.cfg.APIClient, email); exists {
			result.UsersSkipped++
			if k.cfg.Verbose {
				fmt.Fprintf(k.output, "SKIP user %s (already exists)\n", email)
			}
			continue
		}

		displayName := keycloakDisplayName(u)
		metadata := buildKeycloakUserMetadata(u)

		input := client.CreateUserInput{
			Email:       email,
			DisplayName: displayName,
			Metadata:    metadata,
		}

		_, err := k.cfg.APIClient.CreateUser(ctx, input)
		if err != nil {
			if client.IsConflict(err) {
				result.UsersSkipped++
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

		result.UsersCreated++
		if k.cfg.Verbose {
			fmt.Fprintf(k.output, "CREATE user %s\n", email)
		}
	}

	// Clients.
	for _, c := range k.export.Clients {
		if !c.Enabled || c.Protocol != "openid-connect" {
			continue
		}
		name := c.Name
		if name == "" {
			name = c.ClientID
		}
		input := client.CreateClientInput{
			ID:           c.ClientID,
			Name:         name,
			RedirectURIs: c.RedirectURIs,
		}
		if c.PublicClient {
			pkce := true
			input.PKCERequired = &pkce
		}

		_, err := k.cfg.APIClient.CreateClient(ctx, input)
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
		if k.cfg.Verbose {
			fmt.Fprintf(k.output, "CREATE client %s\n", name)
		}
	}

	return result, nil
}

// keycloakUserEmail returns the best email for a Keycloak user, falling back
// to username if it looks like an email.
func keycloakUserEmail(u KeycloakUser) string {
	if u.Email != "" {
		return u.Email
	}
	if strings.Contains(u.Username, "@") {
		return u.Username
	}
	return ""
}

// keycloakDisplayName builds a display name from first/last name or username.
func keycloakDisplayName(u KeycloakUser) string {
	parts := strings.TrimSpace(u.FirstName + " " + u.LastName)
	if parts != "" {
		return parts
	}
	return u.Username
}

// buildKeycloakUserMetadata builds a seki metadata JSON blob preserving
// the original Keycloak user ID, roles, and groups.
func buildKeycloakUserMetadata(u KeycloakUser) json.RawMessage {
	m := map[string]interface{}{
		"keycloak_user_id": u.ID,
	}
	if len(u.RealmRoles) > 0 {
		m["keycloak_realm_roles"] = u.RealmRoles
	}
	if len(u.Groups) > 0 {
		m["keycloak_groups"] = u.Groups
	}
	data, _ := json.Marshal(m)
	return data
}

// isKeycloakDefaultRole returns true for Keycloak built-in roles that should
// not be migrated.
func isKeycloakDefaultRole(name string) bool {
	switch name {
	case "offline_access", "uma_authorization", "default-roles-master":
		return true
	}
	// default-roles-<realm> pattern.
	if strings.HasPrefix(name, "default-roles-") {
		return true
	}
	return false
}

var nonAlphaNum = regexp.MustCompile(`[^a-z0-9]+`)

// slugify creates a URL-safe slug from a name.
func slugify(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = nonAlphaNum.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if s == "" {
		s = "unnamed"
	}
	return s
}

func mustMarshal(v interface{}) json.RawMessage {
	data, _ := json.Marshal(v)
	return data
}
