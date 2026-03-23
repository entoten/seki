package sqlite

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Monet/seki/internal/storage"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

const defaultLimit = 50

// Store implements storage.Storage backed by SQLite.
type Store struct {
	db *sql.DB
}

// New opens a SQLite database at the given DSN (file path or ":memory:").
func New(dsn string) (*Store, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	// Enable WAL mode and foreign keys.
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA foreign_keys=ON",
		"PRAGMA busy_timeout=5000",
	} {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("sqlite: pragma %q: %w", pragma, err)
		}
	}
	return &Store{db: db}, nil
}

// Migrate runs the embedded migration SQL against the database.
func (s *Store) Migrate() error {
	data, err := migrationsFS.ReadFile("migrations/001_init.up.sql")
	if err != nil {
		return fmt.Errorf("sqlite: read migration: %w", err)
	}
	if _, err := s.db.Exec(string(data)); err != nil {
		return fmt.Errorf("sqlite: run migration: %w", err)
	}
	return nil
}

// Close closes the database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// Ping checks database connectivity.
func (s *Store) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

// ---------------------------------------------------------------------------
// UserStore
// ---------------------------------------------------------------------------

func (s *Store) CreateUser(ctx context.Context, user *storage.User) error {
	meta := normalizeJSON(user.Metadata)
	now := timeStr(user.CreatedAt)
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO users (id, email, display_name, disabled, metadata, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		user.ID, user.Email, user.DisplayName, boolToInt(user.Disabled), meta, now, now,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return storage.ErrAlreadyExists
		}
		return fmt.Errorf("sqlite: create user: %w", err)
	}
	return nil
}

func (s *Store) GetUser(ctx context.Context, id string) (*storage.User, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, email, display_name, disabled, metadata, created_at, updated_at
		 FROM users WHERE id = ?`, id)
	return scanUser(row)
}

func (s *Store) GetUserByEmail(ctx context.Context, email string) (*storage.User, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, email, display_name, disabled, metadata, created_at, updated_at
		 FROM users WHERE email = ?`, email)
	return scanUser(row)
}

func (s *Store) UpdateUser(ctx context.Context, user *storage.User) error {
	meta := normalizeJSON(user.Metadata)
	now := timeStr(time.Now().UTC())
	res, err := s.db.ExecContext(ctx,
		`UPDATE users SET email = ?, display_name = ?, disabled = ?, metadata = ?, updated_at = ?
		 WHERE id = ?`,
		user.Email, user.DisplayName, boolToInt(user.Disabled), meta, now, user.ID,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return storage.ErrAlreadyExists
		}
		return fmt.Errorf("sqlite: update user: %w", err)
	}
	return checkRowsAffected(res, "user")
}

func (s *Store) DeleteUser(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("sqlite: delete user: %w", err)
	}
	return checkRowsAffected(res, "user")
}

func (s *Store) ListUsers(ctx context.Context, opts storage.ListOptions) ([]*storage.User, string, error) {
	limit := opts.Limit
	if limit <= 0 {
		limit = defaultLimit
	}
	var rows *sql.Rows
	var err error
	if opts.Cursor != "" {
		rows, err = s.db.QueryContext(ctx,
			`SELECT id, email, display_name, disabled, metadata, created_at, updated_at
			 FROM users WHERE id > ? ORDER BY id ASC LIMIT ?`,
			opts.Cursor, limit+1,
		)
	} else {
		rows, err = s.db.QueryContext(ctx,
			`SELECT id, email, display_name, disabled, metadata, created_at, updated_at
			 FROM users ORDER BY id ASC LIMIT ?`,
			limit+1,
		)
	}
	if err != nil {
		return nil, "", fmt.Errorf("sqlite: list users: %w", err)
	}
	defer rows.Close()

	var users []*storage.User
	for rows.Next() {
		u, err := scanUserFromRows(rows)
		if err != nil {
			return nil, "", err
		}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		return nil, "", fmt.Errorf("sqlite: list users rows: %w", err)
	}

	var nextCursor string
	if len(users) > limit {
		nextCursor = users[limit-1].ID
		users = users[:limit]
	}
	return users, nextCursor, nil
}

// ---------------------------------------------------------------------------
// ClientStore
// ---------------------------------------------------------------------------

func (s *Store) CreateClient(ctx context.Context, client *storage.Client) error {
	redirects, _ := json.Marshal(client.RedirectURIs)
	grants, _ := json.Marshal(client.GrantTypes)
	scopes, _ := json.Marshal(client.Scopes)
	meta := normalizeJSON(client.Metadata)
	now := timeStr(client.CreatedAt)
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO clients (id, name, secret_hash, redirect_uris, grant_types, scopes, pkce_required, metadata, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		client.ID, client.Name, client.SecretHash,
		string(redirects), string(grants), string(scopes),
		boolToInt(client.PKCERequired), meta, now, now,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return storage.ErrAlreadyExists
		}
		return fmt.Errorf("sqlite: create client: %w", err)
	}
	return nil
}

func (s *Store) GetClient(ctx context.Context, id string) (*storage.Client, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, name, secret_hash, redirect_uris, grant_types, scopes, pkce_required, metadata, created_at, updated_at
		 FROM clients WHERE id = ?`, id)
	return scanClient(row)
}

func (s *Store) ListClients(ctx context.Context) ([]*storage.Client, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, secret_hash, redirect_uris, grant_types, scopes, pkce_required, metadata, created_at, updated_at
		 FROM clients ORDER BY id ASC`)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list clients: %w", err)
	}
	defer rows.Close()

	var clients []*storage.Client
	for rows.Next() {
		c, err := scanClientFromRows(rows)
		if err != nil {
			return nil, err
		}
		clients = append(clients, c)
	}
	return clients, rows.Err()
}

func (s *Store) DeleteClient(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM clients WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("sqlite: delete client: %w", err)
	}
	return checkRowsAffected(res, "client")
}

// ---------------------------------------------------------------------------
// SessionStore
// ---------------------------------------------------------------------------

func (s *Store) CreateSession(ctx context.Context, session *storage.Session) error {
	meta := normalizeJSON(session.Metadata)
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions (id, user_id, client_id, ip_address, user_agent, metadata, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		session.ID, session.UserID, session.ClientID,
		session.IPAddress, session.UserAgent, meta,
		timeStr(session.CreatedAt), timeStr(session.ExpiresAt),
	)
	if err != nil {
		return fmt.Errorf("sqlite: create session: %w", err)
	}
	return nil
}

func (s *Store) GetSession(ctx context.Context, id string) (*storage.Session, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, user_id, client_id, ip_address, user_agent, metadata, created_at, expires_at
		 FROM sessions WHERE id = ?`, id)
	return scanSession(row)
}

func (s *Store) DeleteSession(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("sqlite: delete session: %w", err)
	}
	return checkRowsAffected(res, "session")
}

func (s *Store) DeleteExpiredSessions(ctx context.Context) (int64, error) {
	now := timeStr(time.Now().UTC())
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < ?`, now)
	if err != nil {
		return 0, fmt.Errorf("sqlite: delete expired sessions: %w", err)
	}
	return res.RowsAffected()
}

// ---------------------------------------------------------------------------
// AuditStore
// ---------------------------------------------------------------------------

func (s *Store) CreateAuditLog(ctx context.Context, entry *storage.AuditEntry) error {
	meta := normalizeJSON(entry.Metadata)
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO audit_logs (id, actor_id, action, resource, resource_id, ip_address, user_agent, metadata, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.ID, entry.ActorID, entry.Action,
		entry.Resource, entry.ResourceID,
		entry.IPAddress, entry.UserAgent, meta,
		timeStr(entry.CreatedAt),
	)
	if err != nil {
		return fmt.Errorf("sqlite: create audit log: %w", err)
	}
	return nil
}

func (s *Store) ListAuditLogs(ctx context.Context, opts storage.AuditListOptions) ([]*storage.AuditEntry, string, error) {
	limit := opts.Limit
	if limit <= 0 {
		limit = defaultLimit
	}

	query := `SELECT id, actor_id, action, resource, resource_id, ip_address, user_agent, metadata, created_at
		 FROM audit_logs WHERE 1=1`
	args := []any{}

	if opts.ActorID != "" {
		query += ` AND actor_id = ?`
		args = append(args, opts.ActorID)
	}
	if opts.Action != "" {
		query += ` AND action = ?`
		args = append(args, opts.Action)
	}
	if opts.Cursor != "" {
		query += ` AND id > ?`
		args = append(args, opts.Cursor)
	}
	query += ` ORDER BY id ASC LIMIT ?`
	args = append(args, limit+1)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, "", fmt.Errorf("sqlite: list audit logs: %w", err)
	}
	defer rows.Close()

	var entries []*storage.AuditEntry
	for rows.Next() {
		e, err := scanAuditFromRows(rows)
		if err != nil {
			return nil, "", err
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, "", fmt.Errorf("sqlite: list audit logs rows: %w", err)
	}

	var nextCursor string
	if len(entries) > limit {
		nextCursor = entries[limit-1].ID
		entries = entries[:limit]
	}
	return entries, nextCursor, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type scanner interface {
	Scan(dest ...any) error
}

func scanUser(row scanner) (*storage.User, error) {
	var u storage.User
	var disabled int
	var meta string
	var createdAt, updatedAt string
	err := row.Scan(&u.ID, &u.Email, &u.DisplayName, &disabled, &meta, &createdAt, &updatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("sqlite: scan user: %w", err)
	}
	u.Disabled = disabled != 0
	u.Metadata = json.RawMessage(meta)
	u.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	u.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
	return &u, nil
}

func scanUserFromRows(rows *sql.Rows) (*storage.User, error) {
	return scanUser(rows)
}

func scanClient(row scanner) (*storage.Client, error) {
	var c storage.Client
	var redirects, grants, scopes, meta string
	var pkce int
	var createdAt, updatedAt string
	err := row.Scan(&c.ID, &c.Name, &c.SecretHash, &redirects, &grants, &scopes, &pkce, &meta, &createdAt, &updatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("sqlite: scan client: %w", err)
	}
	_ = json.Unmarshal([]byte(redirects), &c.RedirectURIs)
	_ = json.Unmarshal([]byte(grants), &c.GrantTypes)
	_ = json.Unmarshal([]byte(scopes), &c.Scopes)
	c.PKCERequired = pkce != 0
	c.Metadata = json.RawMessage(meta)
	c.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	c.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
	return &c, nil
}

func scanClientFromRows(rows *sql.Rows) (*storage.Client, error) {
	return scanClient(rows)
}

func scanSession(row scanner) (*storage.Session, error) {
	var sess storage.Session
	var meta string
	var createdAt, expiresAt string
	err := row.Scan(&sess.ID, &sess.UserID, &sess.ClientID, &sess.IPAddress, &sess.UserAgent, &meta, &createdAt, &expiresAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("sqlite: scan session: %w", err)
	}
	sess.Metadata = json.RawMessage(meta)
	sess.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	sess.ExpiresAt, _ = time.Parse(time.RFC3339, expiresAt)
	return &sess, nil
}

func scanAuditFromRows(rows *sql.Rows) (*storage.AuditEntry, error) {
	var e storage.AuditEntry
	var meta string
	var createdAt string
	err := rows.Scan(&e.ID, &e.ActorID, &e.Action, &e.Resource, &e.ResourceID, &e.IPAddress, &e.UserAgent, &meta, &createdAt)
	if err != nil {
		return nil, fmt.Errorf("sqlite: scan audit entry: %w", err)
	}
	e.Metadata = json.RawMessage(meta)
	e.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	return &e, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func timeStr(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

func normalizeJSON(raw json.RawMessage) string {
	if len(raw) == 0 {
		return "{}"
	}
	return string(raw)
}

func isUniqueViolation(err error) bool {
	// modernc.org/sqlite returns errors containing "UNIQUE constraint failed".
	return err != nil && (contains(err.Error(), "UNIQUE constraint failed") || contains(err.Error(), "constraint failed: UNIQUE"))
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func checkRowsAffected(res sql.Result, entity string) error {
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("sqlite: rows affected: %w", err)
	}
	if n == 0 {
		return storage.ErrNotFound
	}
	return nil
}
