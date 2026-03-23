package storage

import (
	"context"
	"errors"
	"time"
)

// Common errors returned by storage implementations.
var (
	ErrNotFound      = errors.New("storage: record not found")
	ErrAlreadyExists = errors.New("storage: record already exists")
)

// Storage is the top-level interface combining all store operations.
type Storage interface {
	UserStore
	ClientStore
	SessionStore
	AuditStore
	AuthCodeStore
	RefreshTokenStore
	CredentialStore
	OrgStore
	RoleStore
	Migrate() error
	Close() error
	Ping(ctx context.Context) error
}

// UserStore defines operations on users.
type UserStore interface {
	CreateUser(ctx context.Context, user *User) error
	GetUser(ctx context.Context, id string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	UpdateUser(ctx context.Context, user *User) error
	DeleteUser(ctx context.Context, id string) error
	ListUsers(ctx context.Context, opts ListOptions) ([]*User, string, error) // returns users + next cursor
}

// ClientStore defines operations on OAuth2/OIDC clients.
type ClientStore interface {
	CreateClient(ctx context.Context, client *Client) error
	GetClient(ctx context.Context, id string) (*Client, error)
	ListClients(ctx context.Context) ([]*Client, error)
	DeleteClient(ctx context.Context, id string) error
}

// SessionStore defines operations on user sessions.
type SessionStore interface {
	CreateSession(ctx context.Context, session *Session) error
	GetSession(ctx context.Context, id string) (*Session, error)
	DeleteSession(ctx context.Context, id string) error
	DeleteExpiredSessions(ctx context.Context) (int64, error)
	UpdateSessionActivity(ctx context.Context, id string, lastActive time.Time) error
	DeleteSessionsByUserID(ctx context.Context, userID string) (int64, error)
}

// AuditStore defines operations on audit log entries.
type AuditStore interface {
	CreateAuditLog(ctx context.Context, entry *AuditEntry) error
	ListAuditLogs(ctx context.Context, opts AuditListOptions) ([]*AuditEntry, string, error)
}

// AuthCodeStore defines operations on OAuth2 authorization codes.
type AuthCodeStore interface {
	CreateAuthCode(ctx context.Context, code *AuthCode) error
	GetAuthCode(ctx context.Context, code string) (*AuthCode, error)
	DeleteAuthCode(ctx context.Context, code string) error
}

// CredentialStore defines operations on user credentials (passkey, totp, password).
type CredentialStore interface {
	CreateCredential(ctx context.Context, cred *Credential) error
	GetCredential(ctx context.Context, id string) (*Credential, error)
	GetCredentialByCredentialID(ctx context.Context, credentialID []byte) (*Credential, error)
	GetCredentialsByUserAndType(ctx context.Context, userID string, credType string) ([]*Credential, error)
	ListCredentialsByUser(ctx context.Context, userID string, credType string) ([]*Credential, error)
	UpdateCredential(ctx context.Context, cred *Credential) error
	UpdateCredentialSignCount(ctx context.Context, id string, signCount uint32, lastUsedAt time.Time) error
	DeleteCredential(ctx context.Context, id string) error
	DeleteCredentialsByUserAndType(ctx context.Context, userID string, credType string) error
}

// RefreshTokenStore defines operations on OAuth2 refresh tokens.
type RefreshTokenStore interface {
	CreateRefreshToken(ctx context.Context, token *RefreshToken) error
	GetRefreshTokenByHash(ctx context.Context, hash string) (*RefreshToken, error)
	DeleteRefreshToken(ctx context.Context, id string) error
	DeleteRefreshTokensByFamily(ctx context.Context, family string) (int64, error)
	DeleteRefreshTokensByUserID(ctx context.Context, userID string) (int64, error)
}

// OrgStore defines operations on organizations and their members.
type OrgStore interface {
	CreateOrg(ctx context.Context, org *Organization) error
	GetOrg(ctx context.Context, id string) (*Organization, error)
	GetOrgBySlug(ctx context.Context, slug string) (*Organization, error)
	UpdateOrg(ctx context.Context, org *Organization) error
	DeleteOrg(ctx context.Context, id string) error
	ListOrgs(ctx context.Context, opts ListOptions) ([]*Organization, string, error)

	AddMember(ctx context.Context, member *OrgMember) error
	RemoveMember(ctx context.Context, orgID, userID string) error
	ListMembers(ctx context.Context, orgID string) ([]*OrgMember, error)
	GetMembership(ctx context.Context, orgID, userID string) (*OrgMember, error)
	UpdateMemberRole(ctx context.Context, orgID, userID, role string) error
}

// RoleStore defines operations on roles within organizations.
type RoleStore interface {
	CreateRole(ctx context.Context, role *Role) error
	GetRole(ctx context.Context, id string) (*Role, error)
	GetRoleByName(ctx context.Context, orgID, name string) (*Role, error)
	ListRoles(ctx context.Context, orgID string) ([]*Role, error)
	UpdateRole(ctx context.Context, role *Role) error
	DeleteRole(ctx context.Context, id string) error
}
