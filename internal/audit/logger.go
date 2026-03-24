package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"

	"github.com/Monet/seki/internal/config"
	"github.com/Monet/seki/internal/storage"
)

// Event type constants for audit logging.
const (
	EventUserCreated       = "user.created"
	EventUserLogin         = "user.login"
	EventUserLoginFailed   = "user.login.failed"
	EventUserLogout        = "user.logout"
	EventOrgMemberAdded    = "org.member.added"
	EventOrgMemberRemoved  = "org.member.removed"
	EventClientCreated     = "client.created"
	EventSessionCreated    = "session.created"
	EventTokenIssued       = "token.issued"
	EventTokenRefreshed    = "token.refreshed"
	EventPasskeyRegistered = "passkey.registered"
)

// Event represents a single auditable action.
type Event struct {
	Action     string
	ActorID    string
	Resource   string
	ResourceID string
	IPAddress  string
	UserAgent  string
	Metadata   map[string]interface{}
}

// Logger writes audit entries to the database and optionally to stdout.
type Logger struct {
	store  storage.AuditStore
	output string // "stdout", "webhook", "both", or "" (db only)
}

// NewLogger creates a new audit Logger.
func NewLogger(store storage.AuditStore, cfg config.AuditConfig) *Logger {
	return &Logger{
		store:  store,
		output: cfg.Output,
	}
}

// Log records an audit event to the database and, based on configuration,
// writes a structured JSON line to stdout.
func (l *Logger) Log(ctx context.Context, event Event) error {
	meta, err := json.Marshal(event.Metadata)
	if err != nil {
		meta = []byte("{}")
	}
	if event.Metadata == nil {
		meta = []byte("{}")
	}

	entry := &storage.AuditEntry{
		ID:         uuid.New().String(),
		ActorID:    event.ActorID,
		Action:     event.Action,
		Resource:   event.Resource,
		ResourceID: event.ResourceID,
		IPAddress:  event.IPAddress,
		UserAgent:  event.UserAgent,
		Metadata:   meta,
		CreatedAt:  time.Now().UTC().Truncate(time.Second),
	}

	if err := l.store.CreateAuditLog(ctx, entry); err != nil {
		return fmt.Errorf("audit: store log: %w", err)
	}

	if l.output == "stdout" || l.output == "both" {
		l.writeStdout(entry)
	}

	return nil
}

// LogAuth is a convenience method for logging authentication events.
func (l *Logger) LogAuth(ctx context.Context, action, userID, ip, userAgent string, metadata map[string]interface{}) error {
	return l.Log(ctx, Event{
		Action:    action,
		ActorID:   userID,
		Resource:  "session",
		IPAddress: ip,
		UserAgent: userAgent,
		Metadata:  metadata,
	})
}

// LogAdmin is a convenience method for logging admin operations.
func (l *Logger) LogAdmin(ctx context.Context, action, actorID, resource, resourceID string, metadata map[string]interface{}) error {
	return l.Log(ctx, Event{
		Action:     action,
		ActorID:    actorID,
		Resource:   resource,
		ResourceID: resourceID,
		Metadata:   metadata,
	})
}

// stdoutEntry is the structure written to stdout as a JSON line.
type stdoutEntry struct {
	Timestamp  string                 `json:"timestamp"`
	Action     string                 `json:"action"`
	ActorID    string                 `json:"actor_id"`
	Resource   string                 `json:"resource"`
	ResourceID string                 `json:"resource_id,omitempty"`
	IPAddress  string                 `json:"ip_address,omitempty"`
	UserAgent  string                 `json:"user_agent,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

func (l *Logger) writeStdout(entry *storage.AuditEntry) {
	var meta map[string]interface{}
	_ = json.Unmarshal(entry.Metadata, &meta)

	out := stdoutEntry{
		Timestamp:  entry.CreatedAt.Format(time.RFC3339),
		Action:     entry.Action,
		ActorID:    entry.ActorID,
		Resource:   entry.Resource,
		ResourceID: entry.ResourceID,
		IPAddress:  entry.IPAddress,
		UserAgent:  entry.UserAgent,
		Metadata:   meta,
	}

	data, err := json.Marshal(out)
	if err != nil {
		return
	}
	data = append(data, '\n')
	os.Stdout.Write(data)
}
