package storage

import (
	"encoding/json"
	"time"
)

// User represents a registered user.
type User struct {
	ID            string          `json:"id"`
	Email         string          `json:"email"`
	DisplayName   string          `json:"display_name"`
	Disabled      bool            `json:"disabled"`
	EmailVerified bool            `json:"email_verified"`
	Metadata      json.RawMessage `json:"metadata"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
}

// VerificationToken represents a token for email verification or password reset.
type VerificationToken struct {
	ID        string     `json:"id"`
	UserID    string     `json:"user_id"`
	Type      string     `json:"type"` // "email_verification" or "password_reset"
	TokenHash string     `json:"token_hash"`
	ExpiresAt time.Time  `json:"expires_at"`
	CreatedAt time.Time  `json:"created_at"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
}

// Client represents an OAuth2/OIDC client application.
type Client struct {
	ID                         string          `json:"id"`
	Name                       string          `json:"name"`
	SecretHash                 string          `json:"-"`
	RedirectURIs               []string        `json:"redirect_uris"`
	GrantTypes                 []string        `json:"grant_types"`
	Scopes                     []string        `json:"scopes"`
	PKCERequired               bool            `json:"pkce_required"`
	JWKsURI                    string          `json:"jwks_uri,omitempty"`
	TokenEndpointAuthMethod    string          `json:"token_endpoint_auth_method,omitempty"`
	BackChannelLogoutURI       string          `json:"backchannel_logout_uri,omitempty"`
	BackChannelLogoutSessionReq bool           `json:"backchannel_logout_session_required,omitempty"`
	Metadata                   json.RawMessage `json:"metadata"`
	CreatedAt                  time.Time       `json:"created_at"`
	UpdatedAt                  time.Time       `json:"updated_at"`
}

// Session represents an authenticated user session.
type Session struct {
	ID                string          `json:"id"`
	UserID            string          `json:"user_id"`
	ClientID          string          `json:"client_id"`
	IPAddress         string          `json:"ip_address"`
	UserAgent         string          `json:"user_agent"`
	Metadata          json.RawMessage `json:"metadata"`
	CreatedAt         time.Time       `json:"created_at"`
	ExpiresAt         time.Time       `json:"expires_at"`
	LastActiveAt      time.Time       `json:"last_active_at"`
	AbsoluteExpiresAt time.Time       `json:"absolute_expires_at"`
}

// AuditEntry represents a single audit log record.
type AuditEntry struct {
	ID         string          `json:"id"`
	ActorID    string          `json:"actor_id"`
	Action     string          `json:"action"`
	Resource   string          `json:"resource"`
	ResourceID string          `json:"resource_id"`
	IPAddress  string          `json:"ip_address"`
	UserAgent  string          `json:"user_agent"`
	Metadata   json.RawMessage `json:"metadata"`
	CreatedAt  time.Time       `json:"created_at"`
}

// AuthCode represents an OAuth2 authorization code.
type AuthCode struct {
	Code                string    `json:"code"`
	ClientID            string    `json:"client_id"`
	UserID              string    `json:"user_id"`
	RedirectURI         string    `json:"redirect_uri"`
	Scopes              []string  `json:"scopes"`
	CodeChallenge       string    `json:"code_challenge"`
	CodeChallengeMethod string    `json:"code_challenge_method"`
	Nonce               string    `json:"nonce"`
	State               string    `json:"state"`
	ACR                 string    `json:"acr"` // achieved authentication context class
	ExpiresAt           time.Time `json:"expires_at"`
	CreatedAt           time.Time `json:"created_at"`
}

// ListOptions controls cursor-based pagination for user lists.
type ListOptions struct {
	Cursor string // opaque cursor (user ID for keyset pagination)
	Limit  int    // max items to return; 0 means use default
}

// RefreshToken represents an opaque refresh token stored as a hash.
type RefreshToken struct {
	ID        string    `json:"id"`
	TokenHash string    `json:"token_hash"` // SHA-256 hash of the actual token
	ClientID  string    `json:"client_id"`
	UserID    string    `json:"user_id"`
	Scopes    []string  `json:"scopes"`
	Family    string    `json:"family"` // Token family for rotation tracking
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// Credential represents a stored authentication credential (passkey, totp, password).
type Credential struct {
	ID              string          `json:"id"`
	UserID          string          `json:"user_id"`
	Type            string          `json:"type"`          // "passkey", "totp", "password"
	Secret          []byte          `json:"-"`             // TOTP secret or generic secret
	CredentialID    []byte          `json:"credential_id"` // WebAuthn credential ID
	PublicKey       []byte          `json:"public_key"`    // COSE public key
	AttestationType string          `json:"attestation_type"`
	AAGUID          []byte          `json:"aaguid"`
	SignCount       uint32          `json:"sign_count"`
	DisplayName     string          `json:"display_name"` // user-given name like "MacBook Pro"
	Metadata        json.RawMessage `json:"metadata"`     // extra data (e.g. hashed recovery codes)
	LastUsedAt      *time.Time      `json:"last_used_at"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
}

// PersonalAccessToken represents a personal access token issued to a user.
type PersonalAccessToken struct {
	ID         string     `json:"id"`
	UserID     string     `json:"user_id"`
	Name       string     `json:"name"`
	TokenHash  string     `json:"-"`
	Scopes     []string   `json:"scopes"`
	ExpiresAt  time.Time  `json:"expires_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

// DeviceCode represents a device authorization grant code.
type DeviceCode struct {
	DeviceCode string    `json:"device_code"`
	UserCode   string    `json:"user_code"`
	ClientID   string    `json:"client_id"`
	Scopes     []string  `json:"scopes"`
	Status     string    `json:"status"` // pending, approved, denied, expired
	UserID     string    `json:"user_id,omitempty"`
	ExpiresAt  time.Time `json:"expires_at"`
	Interval   int       `json:"interval"`
	CreatedAt  time.Time `json:"created_at"`
}

// AuditListOptions controls cursor-based pagination and filtering for audit logs.
type AuditListOptions struct {
	Cursor  string // opaque cursor (audit entry ID for keyset pagination)
	Limit   int
	ActorID string    // optional filter
	Action  string    // optional filter
	From    time.Time // optional: only entries created at or after this time
	To      time.Time // optional: only entries created before this time
}

// OrgBranding holds custom branding settings for an organization's login page.
type OrgBranding struct {
	LogoURL         string `json:"logo_url"`
	PrimaryColor    string `json:"primary_color"`
	BackgroundColor string `json:"background_color"`
	CustomCSS       string `json:"custom_css"`
}

// DefaultOrgBranding returns the default branding settings.
func DefaultOrgBranding() OrgBranding {
	return OrgBranding{
		PrimaryColor:    "#0066cc",
		BackgroundColor: "#ffffff",
	}
}

// Organization represents a tenant/organization.
type Organization struct {
	ID        string          `json:"id"`
	Slug      string          `json:"slug"`
	Name      string          `json:"name"`
	Domains   []string        `json:"domains"`
	Branding  OrgBranding     `json:"branding"`
	Metadata  json.RawMessage `json:"metadata"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

// OrgMember represents a user's membership in an organization.
type OrgMember struct {
	OrgID    string    `json:"org_id"`
	UserID   string    `json:"user_id"`
	Role     string    `json:"role"`
	JoinedAt time.Time `json:"joined_at"`
}

// Role represents a named role with permissions within an organization.
type Role struct {
	ID          string    `json:"id"`
	OrgID       string    `json:"org_id"`
	Name        string    `json:"name"`
	Permissions []string  `json:"permissions"`
	CreatedAt   time.Time `json:"created_at"`
}
