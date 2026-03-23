package config

// Config holds the top-level configuration for Seki.
type Config struct {
	Server         ServerConfig          `yaml:"server"`
	Database       DatabaseConfig        `yaml:"database"`
	Signing        SigningConfig         `yaml:"signing"`
	Clients        []ClientConfig        `yaml:"clients"`
	Organizations  []OrganizationConfig  `yaml:"organizations"`
	Authentication AuthenticationConfig  `yaml:"authentication"`
	Audit          AuditConfig           `yaml:"audit"`
	Webhooks       WebhooksConfig        `yaml:"webhooks"`
}

// ServerConfig holds HTTP server settings.
type ServerConfig struct {
	Address string `yaml:"address"`
	Issuer  string `yaml:"issuer"`
}

// DatabaseConfig holds database connection settings.
type DatabaseConfig struct {
	Driver string `yaml:"driver"`
	DSN    string `yaml:"dsn"`
}

// SigningConfig holds token signing settings.
type SigningConfig struct {
	Algorithm string `yaml:"algorithm"`
	KeyFile   string `yaml:"key_file"`
}

// ClientConfig holds an OIDC/OAuth2 client definition.
type ClientConfig struct {
	ID           string   `yaml:"id"`
	Name         string   `yaml:"name"`
	Secret       string   `yaml:"secret"`
	RedirectURIs []string `yaml:"redirect_uris"`
	GrantTypes   []string `yaml:"grant_types"`
	Scopes       []string `yaml:"scopes"`
	PKCERequired bool     `yaml:"pkce_required"`
}

// OrganizationConfig holds a tenant/organization definition.
type OrganizationConfig struct {
	Slug    string       `yaml:"slug"`
	Name    string       `yaml:"name"`
	Domains []string     `yaml:"domains"`
	Roles   []RoleConfig `yaml:"roles"`
}

// RoleConfig holds a role definition within an organization.
type RoleConfig struct {
	Name        string   `yaml:"name"`
	Permissions []string `yaml:"permissions"`
}

// AuthenticationConfig holds authentication method settings.
type AuthenticationConfig struct {
	Passkey  PasskeyConfig             `yaml:"passkey"`
	TOTP     TOTPConfig                `yaml:"totp"`
	Password PasswordConfig            `yaml:"password"`
	Social   map[string]SocialProvider `yaml:"social"`
}

// PasskeyConfig holds WebAuthn/Passkey settings.
type PasskeyConfig struct {
	Enabled bool   `yaml:"enabled"`
	RPName  string `yaml:"rp_name"`
	RPID    string `yaml:"rp_id"`
}

// TOTPConfig holds TOTP settings.
type TOTPConfig struct {
	Enabled bool   `yaml:"enabled"`
	Issuer  string `yaml:"issuer"`
}

// PasswordConfig holds password authentication settings.
type PasswordConfig struct {
	Enabled bool `yaml:"enabled"`
}

// SocialProvider holds a social login provider configuration.
type SocialProvider struct {
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
}

// AuditConfig holds audit logging settings.
type AuditConfig struct {
	Output        string             `yaml:"output"`
	Webhook       AuditWebhookConfig `yaml:"webhook"`
	RetentionDays int                `yaml:"retention_days"`
}

// AuditWebhookConfig holds audit webhook delivery settings.
type AuditWebhookConfig struct {
	URL    string `yaml:"url"`
	Format string `yaml:"format"`
}

// WebhooksConfig holds event webhook settings.
type WebhooksConfig struct {
	Events    []string                `yaml:"events"`
	Endpoints []WebhookEndpointConfig `yaml:"endpoints"`
}

// WebhookEndpointConfig holds a single webhook endpoint.
type WebhookEndpointConfig struct {
	URL    string `yaml:"url"`
	Secret string `yaml:"secret"`
}
