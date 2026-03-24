package session

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/entoten/seki/internal/storage"
)

// ErrExpired indicates that a session has expired (idle or absolute timeout).
var ErrExpired = errors.New("session: expired")

// ErrTooManySessions indicates that the user has reached the maximum number of concurrent sessions.
var ErrTooManySessions = errors.New("session: too many concurrent sessions")

// Config controls session behaviour.
type Config struct {
	IdleTimeout           time.Duration // default 30m — extended on each access
	AbsoluteTimeout       time.Duration // default 24h — never extended
	MaxConcurrentSessions int           // 0 = unlimited; if > 0 oldest sessions are evicted to make room
	CookieName            string
	CookieDomain          string
	CookieSecure          bool
	CookieSameSite        http.SameSite
	CookiePath            string
}

func (c *Config) defaults() {
	if c.IdleTimeout == 0 {
		c.IdleTimeout = 30 * time.Minute
	}
	if c.AbsoluteTimeout == 0 {
		c.AbsoluteTimeout = 24 * time.Hour
	}
	if c.CookieName == "" {
		c.CookieName = "seki_session"
	}
	if c.CookieSameSite == 0 {
		c.CookieSameSite = http.SameSiteLaxMode
	}
	if c.CookiePath == "" {
		c.CookiePath = "/"
	}
}

// Manager handles session lifecycle with DB persistence.
type Manager struct {
	store  storage.SessionStore
	config Config
}

// NewManager creates a session manager.
func NewManager(store storage.SessionStore, cfg Config) *Manager {
	cfg.defaults()
	return &Manager{store: store, config: cfg}
}

// Create builds a new session. Both idle and absolute timeouts are set.
// If MaxConcurrentSessions > 0, the oldest sessions for the user are evicted
// to make room before creating the new one.
func (m *Manager) Create(ctx context.Context, userID, clientID, ip, userAgent string) (*storage.Session, error) {
	// Enforce concurrent session limit by evicting oldest sessions.
	if max := m.config.MaxConcurrentSessions; max > 0 {
		if err := m.evictOldestSessions(ctx, userID, max); err != nil {
			return nil, fmt.Errorf("session: enforce limit: %w", err)
		}
	}

	id, err := generateID()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	sess := &storage.Session{
		ID:                id,
		UserID:            userID,
		ClientID:          clientID,
		IPAddress:         ip,
		UserAgent:         userAgent,
		CreatedAt:         now,
		ExpiresAt:         now.Add(m.config.IdleTimeout),
		LastActiveAt:      now,
		AbsoluteExpiresAt: now.Add(m.config.AbsoluteTimeout),
	}
	if err := m.store.CreateSession(ctx, sess); err != nil {
		return nil, fmt.Errorf("session: create: %w", err)
	}
	return sess, nil
}

// evictOldestSessions deletes the oldest sessions for a user so that at most
// (max - 1) sessions remain, leaving room for one new session.
func (m *Manager) evictOldestSessions(ctx context.Context, userID string, max int) error {
	sessions, err := m.store.ListSessionsByUserID(ctx, userID)
	if err != nil {
		return err
	}
	// Need to leave room for the new session we're about to create.
	excess := len(sessions) - (max - 1)
	if excess <= 0 {
		return nil
	}
	// Sessions are returned ordered by created_at ASC (oldest first).
	for i := 0; i < excess; i++ {
		if err := m.store.DeleteSession(ctx, sessions[i].ID); err != nil {
			return fmt.Errorf("evict session %s: %w", sessions[i].ID, err)
		}
	}
	return nil
}

// ListByUserID returns all active sessions for the given user.
func (m *Manager) ListByUserID(ctx context.Context, userID string) ([]*storage.Session, error) {
	return m.store.ListSessionsByUserID(ctx, userID)
}

// Get retrieves and validates a session. It checks both idle and absolute
// timeouts and bumps the idle window on valid access.
func (m *Manager) Get(ctx context.Context, sessionID string) (*storage.Session, error) {
	sess, err := m.store.GetSession(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	// Absolute timeout — never extended.
	if now.After(sess.AbsoluteExpiresAt) {
		_ = m.store.DeleteSession(ctx, sessionID)
		return nil, ErrExpired
	}
	// Idle timeout.
	if now.After(sess.ExpiresAt) {
		_ = m.store.DeleteSession(ctx, sessionID)
		return nil, ErrExpired
	}
	// Bump idle window.
	newExpiry := now.Add(m.config.IdleTimeout)
	// Don't extend past absolute timeout.
	if newExpiry.After(sess.AbsoluteExpiresAt) {
		newExpiry = sess.AbsoluteExpiresAt
	}
	sess.LastActiveAt = now
	sess.ExpiresAt = newExpiry
	_ = m.store.UpdateSessionActivity(ctx, sessionID, now)
	return sess, nil
}

// UpdateMetadata replaces the metadata JSON on an existing session.
func (m *Manager) UpdateMetadata(ctx context.Context, sessionID string, metadata json.RawMessage) error {
	return m.store.UpdateSessionMetadata(ctx, sessionID, metadata)
}

// Delete invalidates a session (logout).
func (m *Manager) Delete(ctx context.Context, sessionID string) error {
	return m.store.DeleteSession(ctx, sessionID)
}

// DeleteByUserID invalidates all sessions for a user.
func (m *Manager) DeleteByUserID(ctx context.Context, userID string) (int64, error) {
	return m.store.DeleteSessionsByUserID(ctx, userID)
}

// Rotate creates a new session for the same user and deletes the old one.
// Use after login to prevent session fixation.
func (m *Manager) Rotate(ctx context.Context, oldSessionID string) (*storage.Session, error) {
	old, err := m.store.GetSession(ctx, oldSessionID)
	if err != nil {
		return nil, fmt.Errorf("session: rotate get: %w", err)
	}
	newSess, err := m.Create(ctx, old.UserID, old.ClientID, old.IPAddress, old.UserAgent)
	if err != nil {
		return nil, fmt.Errorf("session: rotate create: %w", err)
	}
	_ = m.store.DeleteSession(ctx, oldSessionID)
	return newSess, nil
}

// Cleanup removes all expired sessions. Call periodically.
func (m *Manager) Cleanup(ctx context.Context) (int64, error) {
	return m.store.DeleteExpiredSessions(ctx)
}

// --- HTTP Cookie helpers ---

// SetCookie writes the session cookie to the response.
func (m *Manager) SetCookie(w http.ResponseWriter, sess *storage.Session) {
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- security attributes are configurable via session.Config
		Name:     m.config.CookieName,
		Value:    sess.ID,
		Path:     m.config.CookiePath,
		Domain:   m.config.CookieDomain,
		MaxAge:   int(m.config.AbsoluteTimeout.Seconds()),
		HttpOnly: true,
		Secure:   m.config.CookieSecure,
		SameSite: m.config.CookieSameSite,
	})
}

// ClearCookie removes the session cookie.
func (m *Manager) ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- security attributes are configurable via session.Config
		Name:     m.config.CookieName,
		Value:    "",
		Path:     m.config.CookiePath,
		Domain:   m.config.CookieDomain,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   m.config.CookieSecure,
		SameSite: m.config.CookieSameSite,
	})
}

// GetSessionID reads the session ID from the request cookie.
func (m *Manager) GetSessionID(r *http.Request) (string, error) {
	c, err := r.Cookie(m.config.CookieName)
	if err != nil {
		return "", err
	}
	return c.Value, nil
}

func generateID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("session: generate id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
