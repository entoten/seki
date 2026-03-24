package config

// Config holds the top-level configuration for Seki.
type Config struct {
	Server         ServerConfig         `yaml:"server"`
	Database       DatabaseConfig       `yaml:"database"`
	Signing        SigningConfig        `yaml:"signing"`
	Clients        []ClientConfig       `yaml:"clients"`
	Organizations  []OrganizationConfig `yaml:"organizations"`
	Authentication AuthenticationConfig `yaml:"authentication"`
	Session        SessionConfig        `yaml:"session"`
	Audit          AuditConfig          `yaml:"audit"`
	Webhooks       WebhooksConfig       `yaml:"webhooks"`
	Admin          AdminConfig          `yaml:"admin"`
	RateLimit      RateLimitConfig      `yaml:"rate_limit"`
	CORS           CORSConfig           `yaml:"cors"`
	Log            LogConfig            `yaml:"log"`
	Telemetry      TelemetryConfig      `yaml:"telemetry"`
	Debug          DebugConfig          `yaml:"debug"`
}

// TelemetryConfig holds OpenTelemetry tracing settings.
type TelemetryConfig struct {
	Enabled      bool   `yaml:"enabled"`
	OTLPEndpoint string `yaml:"otlp_endpoint"` // e.g. "localhost:4318"
	ServiceName  string `yaml:"service_name"`  // default "seki"
}

// DebugConfig holds debugging and profiling settings.
type DebugConfig struct {
	PprofEnabled bool `yaml:"pprof_enabled"`
}

// LogConfig holds structured logging settings.
type LogConfig struct {
	Level  string `yaml:"level"`  // debug, info, warn, error (default: info)
	Format string `yaml:"format"` // json, text (default: json)
}

// RateLimitConfig holds rate limiting and brute-force protection settings.
type RateLimitConfig struct {
	Enabled          bool   `yaml:"enabled"`
	RequestsPerMin   int    `yaml:"requests_per_min"`
	LoginAttemptsMax int    `yaml:"login_attempts_max"`
	LockoutDuration  string `yaml:"lockout_duration"`
}

// CORSConfig holds Cross-Origin Resource Sharing settings.
type CORSConfig struct {
	AllowedOrigins   []string `yaml:"allowed_origins"`   // e.g. ["https://app.example.com"]
	AllowedMethods   []string `yaml:"allowed_methods"`   // default: GET, POST, PATCH, DELETE, OPTIONS
	AllowedHeaders   []string `yaml:"allowed_headers"`   // default: Authorization, Content-Type, X-API-Key
	AllowCredentials bool     `yaml:"allow_credentials"` // default: true
	MaxAge           int      `yaml:"max_age"`           // preflight cache seconds, default: 3600
}

// AdminConfig holds settings for the Admin REST API.
type AdminConfig struct {
	APIKeys []string `yaml:"api_keys"`
}

// ServerConfig holds HTTP server settings.
type ServerConfig struct {
	Address        string   `yaml:"address"`
	Issuer         string   `yaml:"issuer"`
	TrustedProxies []string `yaml:"trusted_proxies"` // CIDRs of trusted reverse proxies
}

// SessionConfig holds session management settings.
type SessionConfig struct {
	MaxConcurrentSessions int `yaml:"max_concurrent_sessions"` // 0 = unlimited
}

// DatabaseConfig holds database connection settings.
type DatabaseConfig struct {
	Driver          string `yaml:"driver"`
	DSN             string `yaml:"dsn"`
	MaxOpenConns    int    `yaml:"max_open_conns"`     // default: 25
	MaxIdleConns    int    `yaml:"max_idle_conns"`     // default: 5
	ConnMaxLifetime string `yaml:"conn_max_lifetime"`  // default: "5m"
	ConnMaxIdleTime string `yaml:"conn_max_idle_time"` // default: "1m"
}

// SigningConfig holds token signing settings.
type SigningConfig struct {
	Algorithm   string   `yaml:"algorithm"`
	KeyFile     string   `yaml:"key_file"`
	OldKeyFiles []string `yaml:"old_key_files"`  // rotated keys still valid for verification
	RotationTTL string   `yaml:"rotation_ttl"`   // how long old keys stay valid
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
	Passkey   PasskeyConfig             `yaml:"passkey"`
	TOTP      TOTPConfig                `yaml:"totp"`
	Password  PasswordConfig            `yaml:"password"`
	MagicLink MagicLinkConfig           `yaml:"magic_link"`
	Social    map[string]SocialProvider `yaml:"social"`
	JIT       JITConfig                 `yaml:"jit"`
}

// JITConfig holds Just-In-Time provisioning settings.
type JITConfig struct {
	Enabled     bool   `yaml:"enabled"`
	DefaultRole string `yaml:"default_role"` // default "member"
}

// MagicLinkConfig holds magic link / email OTP authentication settings.
type MagicLinkConfig struct {
	Enabled    bool   `yaml:"enabled"`
	CodeLength int    `yaml:"code_length"` // default 6
	TTL        string `yaml:"ttl"`         // default "10m"
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
	URL    string   `yaml:"url"`
	Secret string   `yaml:"secret"`
	Events []string `yaml:"events"` // event filter; empty means all events
}
