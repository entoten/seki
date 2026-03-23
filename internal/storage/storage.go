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
