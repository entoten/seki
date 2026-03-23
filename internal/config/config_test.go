package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validYAML = `
server:
  address: ":9090"
  issuer: "https://auth.example.com"

database:
  driver: postgres
  dsn: "postgres://seki:secret@localhost:5432/seki?sslmode=disable"

signing:
  algorithm: EdDSA
  key_file: /etc/seki/keys/signing.key

clients:
  - id: my-app
    name: "My App"
    redirect_uris:
      - "https://app.example.com/callback"
    grant_types:
      - authorization_code
    scopes:
      - openid
      - profile
    pkce_required: true

  - id: backend-worker
    name: "Backend Service"
    grant_types:
      - client_credentials
    scopes:
      - admin:read

organizations:
  - slug: acme-corp
    name: "Acme Corporation"
    domains:
      - acme-corp.com
    roles:
      - name: admin
        permissions: ["org:manage", "users:write"]
      - name: member
        permissions: ["users:read"]

authentication:
  passkey:
    enabled: true
    rp_name: "seki"
    rp_id: "auth.example.com"
  totp:
    enabled: true
    issuer: "seki"
  password:
    enabled: false
  social:
    google:
      client_id: "google-id"
      client_secret: "google-secret"

audit:
  output: both
  webhook:
    url: "https://siem.example.com/ingest"
    format: json
  retention_days: 90

webhooks:
  events:
    - user.created
    - user.login
  endpoints:
    - url: "https://app.example.com/webhooks/auth"
      secret: "wh-secret"
`

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "seki.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadValidConfig(t *testing.T) {
	path := writeTemp(t, validYAML)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Server
	if cfg.Server.Address != ":9090" {
		t.Errorf("server.address = %q, want %q", cfg.Server.Address, ":9090")
	}
	if cfg.Server.Issuer != "https://auth.example.com" {
		t.Errorf("server.issuer = %q, want %q", cfg.Server.Issuer, "https://auth.example.com")
	}

	// Database
	if cfg.Database.Driver != "postgres" {
		t.Errorf("database.driver = %q, want %q", cfg.Database.Driver, "postgres")
	}

	// Signing
	if cfg.Signing.Algorithm != "EdDSA" {
		t.Errorf("signing.algorithm = %q, want %q", cfg.Signing.Algorithm, "EdDSA")
	}

	// Clients
	if len(cfg.Clients) != 2 {
		t.Fatalf("len(clients) = %d, want 2", len(cfg.Clients))
	}
	if cfg.Clients[0].ID != "my-app" {
		t.Errorf("clients[0].id = %q, want %q", cfg.Clients[0].ID, "my-app")
	}
	if !cfg.Clients[0].PKCERequired {
		t.Error("clients[0].pkce_required should be true")
	}
	if len(cfg.Clients[0].RedirectURIs) != 1 {
		t.Errorf("clients[0].redirect_uris len = %d, want 1", len(cfg.Clients[0].RedirectURIs))
	}

	// Organizations
	if len(cfg.Organizations) != 1 {
		t.Fatalf("len(organizations) = %d, want 1", len(cfg.Organizations))
	}
	if cfg.Organizations[0].Slug != "acme-corp" {
		t.Errorf("organizations[0].slug = %q, want %q", cfg.Organizations[0].Slug, "acme-corp")
	}
	if len(cfg.Organizations[0].Roles) != 2 {
		t.Errorf("len(organizations[0].roles) = %d, want 2", len(cfg.Organizations[0].Roles))
	}

	// Authentication
	if !cfg.Authentication.Passkey.Enabled {
		t.Error("authentication.passkey.enabled should be true")
	}
	if cfg.Authentication.Password.Enabled {
		t.Error("authentication.password.enabled should be false")
	}
	if cfg.Authentication.Social["google"].ClientID != "google-id" {
		t.Errorf("social.google.client_id = %q, want %q", cfg.Authentication.Social["google"].ClientID, "google-id")
	}

	// Audit
	if cfg.Audit.Output != "both" {
		t.Errorf("audit.output = %q, want %q", cfg.Audit.Output, "both")
	}
	if cfg.Audit.RetentionDays != 90 {
		t.Errorf("audit.retention_days = %d, want 90", cfg.Audit.RetentionDays)
	}

	// Webhooks
	if len(cfg.Webhooks.Events) != 2 {
		t.Errorf("len(webhooks.events) = %d, want 2", len(cfg.Webhooks.Events))
	}
	if len(cfg.Webhooks.Endpoints) != 1 {
		t.Errorf("len(webhooks.endpoints) = %d, want 1", len(cfg.Webhooks.Endpoints))
	}
}

func TestEnvVarExpansion(t *testing.T) {
	t.Setenv("SEKI_TEST_SECRET", "expanded-value")

	yaml := `
server:
  issuer: "https://auth.example.com"
database:
  driver: sqlite
  dsn: "${SEKI_TEST_SECRET}"
`
	path := writeTemp(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Database.DSN != "expanded-value" {
		t.Errorf("database.dsn = %q, want %q", cfg.Database.DSN, "expanded-value")
	}
}

func TestEnvVarUnsetExpandsToEmpty(t *testing.T) {
	os.Unsetenv("SEKI_UNSET_VAR_XYZ")

	yaml := `
server:
  issuer: "https://auth.example.com"
database:
  driver: sqlite
  dsn: "prefix-${SEKI_UNSET_VAR_XYZ}-suffix"
`
	path := writeTemp(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Database.DSN != "prefix--suffix" {
		t.Errorf("database.dsn = %q, want %q", cfg.Database.DSN, "prefix--suffix")
	}
}

func TestValidationMissingIssuer(t *testing.T) {
	yaml := `
database:
  driver: postgres
`
	path := writeTemp(t, yaml)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
	if !strings.Contains(err.Error(), "server.issuer is required") {
		t.Errorf("error should mention server.issuer, got: %v", err)
	}
}

func TestValidationMissingDriver(t *testing.T) {
	yaml := `
server:
  issuer: "https://auth.example.com"
`
	path := writeTemp(t, yaml)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
	if !strings.Contains(err.Error(), "database.driver is required") {
		t.Errorf("error should mention database.driver, got: %v", err)
	}
}

func TestValidationInvalidDriver(t *testing.T) {
	yaml := `
server:
  issuer: "https://auth.example.com"
database:
  driver: mysql
`
	path := writeTemp(t, yaml)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
	if !strings.Contains(err.Error(), "must be") {
		t.Errorf("error should mention valid drivers, got: %v", err)
	}
}

func TestValidationClientMissingID(t *testing.T) {
	yaml := `
server:
  issuer: "https://auth.example.com"
database:
  driver: postgres
clients:
  - name: "No ID Client"
`
	path := writeTemp(t, yaml)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
	if !strings.Contains(err.Error(), "clients[0].id is required") {
		t.Errorf("error should mention clients[0].id, got: %v", err)
	}
}

func TestDefaults(t *testing.T) {
	yaml := `
server:
  issuer: "https://auth.example.com"
database:
  driver: sqlite
`
	path := writeTemp(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Server.Address != ":8080" {
		t.Errorf("default server.address = %q, want %q", cfg.Server.Address, ":8080")
	}
	if cfg.Signing.Algorithm != "EdDSA" {
		t.Errorf("default signing.algorithm = %q, want %q", cfg.Signing.Algorithm, "EdDSA")
	}
	if cfg.Audit.Output != "stdout" {
		t.Errorf("default audit.output = %q, want %q", cfg.Audit.Output, "stdout")
	}
}

func TestLoadFileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/path/seki.yaml")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestLoadInvalidYAML(t *testing.T) {
	path := writeTemp(t, "{{invalid yaml")
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML, got nil")
	}
}

func TestLoadDefaultPath(t *testing.T) {
	// Passing empty string should use DefaultPath, which won't exist in temp.
	_, err := Load("")
	if err == nil {
		t.Fatal("expected error when default path doesn't exist")
	}
}
