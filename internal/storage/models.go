package storage

import (
	"encoding/json"
	"time"
)

// User represents a registered user.
type User struct {
	ID          string          `json:"id"`
	Email       string          `json:"email"`
	DisplayName string          `json:"display_name"`
	Disabled    bool            `json:"disabled"`
	Metadata    json.RawMessage `json:"metadata"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

// Client represents an OAuth2/OIDC client application.
type Client struct {
	ID           string          `json:"id"`
	Name         string          `json:"name"`
	SecretHash   string          `json:"-"`
	RedirectURIs []string        `json:"redirect_uris"`
	GrantTypes   []string        `json:"grant_types"`
	Scopes       []string        `json:"scopes"`
	PKCERequired bool            `json:"pkce_required"`
	Metadata     json.RawMessage `json:"metadata"`
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`
}

// Session represents an authenticated user session.
type Session struct {
	ID        string          `json:"id"`
	UserID    string          `json:"user_id"`
	ClientID  string          `json:"client_id"`
	IPAddress string          `json:"ip_address"`
	UserAgent string          `json:"user_agent"`
	Metadata  json.RawMessage `json:"metadata"`
	CreatedAt time.Time       `json:"created_at"`
	ExpiresAt time.Time       `json:"expires_at"`
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

// ListOptions controls cursor-based pagination for user lists.
type ListOptions struct {
	Cursor string // opaque cursor (user ID for keyset pagination)
	Limit  int    // max items to return; 0 means use default
}

// AuditListOptions controls cursor-based pagination and filtering for audit logs.
type AuditListOptions struct {
	Cursor   string // opaque cursor (audit entry ID for keyset pagination)
	Limit    int
	ActorID  string // optional filter
	Action   string // optional filter
}
