package postgres

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Monet/seki/internal/storage"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

const defaultLimit = 50

// Store implements storage.Storage backed by PostgreSQL via pgx.
type Store struct {
	pool *pgxpool.Pool
}

// New creates a new PostgreSQL-backed store with a connection pool.
func New(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres: ping: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Migrate runs the embedded migration SQL files against the database in order.
func (s *Store) Migrate() error {
	migrations := []string{
		"migrations/001_init.up.sql",
		"migrations/002_authorization_codes.up.sql",
	}
	for _, name := range migrations {
		data, err := migrationsFS.ReadFile(name)
		if err != nil {
			return fmt.Errorf("postgres: read migration %s: %w", name, err)
		}
		if _, err := s.pool.Exec(context.Background(), string(data)); err != nil {
			return fmt.Errorf("postgres: run migration %s: %w", name, err)
		}
	}
	return nil
}

// Close closes the connection pool.
func (s *Store) Close() error {
	s.pool.Close()
	return nil
}

// Ping checks database connectivity.
func (s *Store) Ping(ctx context.Context) error {
	return s.pool.Ping(ctx)
}

// ---------------------------------------------------------------------------
// UserStore
// ---------------------------------------------------------------------------

func (s *Store) CreateUser(ctx context.Context, user *storage.User) error {
	meta := normalizeJSON(user.Metadata)
	now := user.CreatedAt.UTC()
	_, err := s.pool.Exec(ctx,
		`INSERT INTO users (id, email, display_name, disabled, metadata, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		user.ID, user.Email, user.DisplayName, user.Disabled, meta, now, now,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return storage.ErrAlreadyExists
		}
		return fmt.Errorf("postgres: create user: %w", err)
	}
	return nil
}

func (s *Store) GetUser(ctx context.Context, id string) (*storage.User, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, email, display_name, disabled, metadata, created_at, updated_at
		 FROM users WHERE id = $1`, id)
	return scanUser(row)
}

func (s *Store) GetUserByEmail(ctx context.Context, email string) (*storage.User, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, email, display_name, disabled, metadata, created_at, updated_at
		 FROM users WHERE email = $1`, email)
	return scanUser(row)
}

func (s *Store) UpdateUser(ctx context.Context, user *storage.User) error {
	meta := normalizeJSON(user.Metadata)
	now := time.Now().UTC()
	ct, err := s.pool.Exec(ctx,
		`UPDATE users SET email = $1, display_name = $2, disabled = $3, metadata = $4, updated_at = $5
		 WHERE id = $6`,
		user.Email, user.DisplayName, user.Disabled, meta, now, user.ID,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return storage.ErrAlreadyExists
		}
		return fmt.Errorf("postgres: update user: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *Store) DeleteUser(ctx context.Context, id string) error {
	ct, err := s.pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("postgres: delete user: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *Store) ListUsers(ctx context.Context, opts storage.ListOptions) ([]*storage.User, string, error) {
	limit := opts.Limit
	if limit <= 0 {
		limit = defaultLimit
	}
	var rows pgx.Rows
	var err error
	if opts.Cursor != "" {
		rows, err = s.pool.Query(ctx,
			`SELECT id, email, display_name, disabled, metadata, created_at, updated_at
			 FROM users WHERE id > $1 ORDER BY id ASC LIMIT $2`,
			opts.Cursor, limit+1,
		)
	} else {
		rows, err = s.pool.Query(ctx,
			`SELECT id, email, display_name, disabled, metadata, created_at, updated_at
			 FROM users ORDER BY id ASC LIMIT $1`,
			limit+1,
		)
	}
	if err != nil {
		return nil, "", fmt.Errorf("postgres: list users: %w", err)
	}
	defer rows.Close()

	var users []*storage.User
	for rows.Next() {
		u, err := scanUserPgx(rows)
		if err != nil {
			return nil, "", err
		}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		return nil, "", fmt.Errorf("postgres: list users rows: %w", err)
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
	now := client.CreatedAt.UTC()
	_, err := s.pool.Exec(ctx,
		`INSERT INTO clients (id, name, secret_hash, redirect_uris, grant_types, scopes, pkce_required, metadata, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		client.ID, client.Name, client.SecretHash,
		string(redirects), string(grants), string(scopes),
		client.PKCERequired, meta, now, now,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return storage.ErrAlreadyExists
		}
		return fmt.Errorf("postgres: create client: %w", err)
	}
	return nil
}

func (s *Store) GetClient(ctx context.Context, id string) (*storage.Client, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, name, secret_hash, redirect_uris, grant_types, scopes, pkce_required, metadata, created_at, updated_at
		 FROM clients WHERE id = $1`, id)
	return scanClientPgx(row)
}

func (s *Store) ListClients(ctx context.Context) ([]*storage.Client, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, name, secret_hash, redirect_uris, grant_types, scopes, pkce_required, metadata, created_at, updated_at
		 FROM clients ORDER BY id ASC`)
	if err != nil {
		return nil, fmt.Errorf("postgres: list clients: %w", err)
	}
	defer rows.Close()

	var clients []*storage.Client
	for rows.Next() {
		c, err := scanClientPgxRows(rows)
		if err != nil {
			return nil, err
		}
		clients = append(clients, c)
	}
	return clients, rows.Err()
}

func (s *Store) DeleteClient(ctx context.Context, id string) error {
	ct, err := s.pool.Exec(ctx, `DELETE FROM clients WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("postgres: delete client: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

// ---------------------------------------------------------------------------
// SessionStore
// ---------------------------------------------------------------------------

func (s *Store) CreateSession(ctx context.Context, session *storage.Session) error {
	meta := normalizeJSON(session.Metadata)
	_, err := s.pool.Exec(ctx,
		`INSERT INTO sessions (id, user_id, client_id, ip_address, user_agent, metadata, created_at, expires_at, last_active_at, absolute_expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		session.ID, session.UserID, session.ClientID,
		session.IPAddress, session.UserAgent, meta,
		session.CreatedAt.UTC(), session.ExpiresAt.UTC(),
		session.LastActiveAt.UTC(), session.AbsoluteExpiresAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("postgres: create session: %w", err)
	}
	return nil
}

func (s *Store) GetSession(ctx context.Context, id string) (*storage.Session, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, user_id, client_id, ip_address, user_agent, metadata, created_at, expires_at, last_active_at, absolute_expires_at
		 FROM sessions WHERE id = $1`, id)
	var sess storage.Session
	var meta []byte
	err := row.Scan(&sess.ID, &sess.UserID, &sess.ClientID, &sess.IPAddress, &sess.UserAgent, &meta, &sess.CreatedAt, &sess.ExpiresAt, &sess.LastActiveAt, &sess.AbsoluteExpiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("postgres: scan session: %w", err)
	}
	sess.Metadata = json.RawMessage(meta)
	return &sess, nil
}

func (s *Store) DeleteSession(ctx context.Context, id string) error {
	ct, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("postgres: delete session: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *Store) DeleteExpiredSessions(ctx context.Context) (int64, error) {
	now := time.Now().UTC()
	ct, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE expires_at < $1 OR absolute_expires_at < $1`, now)
	if err != nil {
		return 0, fmt.Errorf("postgres: delete expired sessions: %w", err)
	}
	return ct.RowsAffected(), nil
}

func (s *Store) UpdateSessionActivity(ctx context.Context, id string, lastActive time.Time) error {
	ct, err := s.pool.Exec(ctx,
		`UPDATE sessions SET last_active_at = $1 WHERE id = $2`,
		lastActive.UTC(), id,
	)
	if err != nil {
		return fmt.Errorf("postgres: update session activity: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *Store) DeleteSessionsByUserID(ctx context.Context, userID string) (int64, error) {
	ct, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, userID)
	if err != nil {
		return 0, fmt.Errorf("postgres: delete sessions by user: %w", err)
	}
	return ct.RowsAffected(), nil
}

// ---------------------------------------------------------------------------
// AuditStore
// ---------------------------------------------------------------------------

func (s *Store) CreateAuditLog(ctx context.Context, entry *storage.AuditEntry) error {
	meta := normalizeJSON(entry.Metadata)
	_, err := s.pool.Exec(ctx,
		`INSERT INTO audit_logs (id, actor_id, action, resource, resource_id, ip_address, user_agent, metadata, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		entry.ID, entry.ActorID, entry.Action,
		entry.Resource, entry.ResourceID,
		entry.IPAddress, entry.UserAgent, meta,
		entry.CreatedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("postgres: create audit log: %w", err)
	}
	return nil
}

func (s *Store) ListAuditLogs(ctx context.Context, opts storage.AuditListOptions) ([]*storage.AuditEntry, string, error) {
	limit := opts.Limit
	if limit <= 0 {
		limit = defaultLimit
	}

	query := `SELECT id, actor_id, action, resource, resource_id, ip_address, user_agent, metadata, created_at
		 FROM audit_logs WHERE TRUE`
	args := []any{}
	argIdx := 1

	if opts.ActorID != "" {
		query += fmt.Sprintf(` AND actor_id = $%d`, argIdx)
		args = append(args, opts.ActorID)
		argIdx++
	}
	if opts.Action != "" {
		query += fmt.Sprintf(` AND action = $%d`, argIdx)
		args = append(args, opts.Action)
		argIdx++
	}
	if opts.Cursor != "" {
		query += fmt.Sprintf(` AND id > $%d`, argIdx)
		args = append(args, opts.Cursor)
		argIdx++
	}
	query += fmt.Sprintf(` ORDER BY id ASC LIMIT $%d`, argIdx)
	args = append(args, limit+1)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, "", fmt.Errorf("postgres: list audit logs: %w", err)
	}
	defer rows.Close()

	var entries []*storage.AuditEntry
	for rows.Next() {
		var e storage.AuditEntry
		var meta []byte
		err := rows.Scan(&e.ID, &e.ActorID, &e.Action, &e.Resource, &e.ResourceID, &e.IPAddress, &e.UserAgent, &meta, &e.CreatedAt)
		if err != nil {
			return nil, "", fmt.Errorf("postgres: scan audit entry: %w", err)
		}
		e.Metadata = json.RawMessage(meta)
		entries = append(entries, &e)
	}
	if err := rows.Err(); err != nil {
		return nil, "", fmt.Errorf("postgres: list audit logs rows: %w", err)
	}

	var nextCursor string
	if len(entries) > limit {
		nextCursor = entries[limit-1].ID
		entries = entries[:limit]
	}
	return entries, nextCursor, nil
}

// ---------------------------------------------------------------------------
// AuthCodeStore
// ---------------------------------------------------------------------------

func (s *Store) CreateAuthCode(ctx context.Context, code *storage.AuthCode) error {
	scopes, _ := json.Marshal(code.Scopes)
	_, err := s.pool.Exec(ctx,
		`INSERT INTO authorization_codes (code, client_id, user_id, redirect_uri, scopes, code_challenge, code_challenge_method, nonce, state, expires_at, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		code.Code, code.ClientID, code.UserID, code.RedirectURI,
		string(scopes), code.CodeChallenge, code.CodeChallengeMethod,
		code.Nonce, code.State,
		code.ExpiresAt.UTC(), code.CreatedAt.UTC(),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return storage.ErrAlreadyExists
		}
		return fmt.Errorf("postgres: create auth code: %w", err)
	}
	return nil
}

func (s *Store) GetAuthCode(ctx context.Context, code string) (*storage.AuthCode, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT code, client_id, user_id, redirect_uri, scopes, code_challenge, code_challenge_method, nonce, state, expires_at, created_at
		 FROM authorization_codes WHERE code = $1`, code)
	var ac storage.AuthCode
	var scopes []byte
	err := row.Scan(&ac.Code, &ac.ClientID, &ac.UserID, &ac.RedirectURI, &scopes, &ac.CodeChallenge, &ac.CodeChallengeMethod, &ac.Nonce, &ac.State, &ac.ExpiresAt, &ac.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("postgres: scan auth code: %w", err)
	}
	_ = json.Unmarshal(scopes, &ac.Scopes)
	return &ac, nil
}

func (s *Store) DeleteAuthCode(ctx context.Context, code string) error {
	ct, err := s.pool.Exec(ctx, `DELETE FROM authorization_codes WHERE code = $1`, code)
	if err != nil {
		return fmt.Errorf("postgres: delete auth code: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func scanUser(row pgx.Row) (*storage.User, error) {
	var u storage.User
	var meta []byte
	err := row.Scan(&u.ID, &u.Email, &u.DisplayName, &u.Disabled, &meta, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("postgres: scan user: %w", err)
	}
	u.Metadata = json.RawMessage(meta)
	return &u, nil
}

func scanUserPgx(rows pgx.Rows) (*storage.User, error) {
	var u storage.User
	var meta []byte
	err := rows.Scan(&u.ID, &u.Email, &u.DisplayName, &u.Disabled, &meta, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("postgres: scan user: %w", err)
	}
	u.Metadata = json.RawMessage(meta)
	return &u, nil
}

func scanClientPgx(row pgx.Row) (*storage.Client, error) {
	var c storage.Client
	var redirects, grants, scopes, meta []byte
	err := row.Scan(&c.ID, &c.Name, &c.SecretHash, &redirects, &grants, &scopes, &c.PKCERequired, &meta, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("postgres: scan client: %w", err)
	}
	_ = json.Unmarshal(redirects, &c.RedirectURIs)
	_ = json.Unmarshal(grants, &c.GrantTypes)
	_ = json.Unmarshal(scopes, &c.Scopes)
	c.Metadata = json.RawMessage(meta)
	return &c, nil
}

func scanClientPgxRows(rows pgx.Rows) (*storage.Client, error) {
	var c storage.Client
	var redirects, grants, scopes, meta []byte
	err := rows.Scan(&c.ID, &c.Name, &c.SecretHash, &redirects, &grants, &scopes, &c.PKCERequired, &meta, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("postgres: scan client: %w", err)
	}
	_ = json.Unmarshal(redirects, &c.RedirectURIs)
	_ = json.Unmarshal(grants, &c.GrantTypes)
	_ = json.Unmarshal(scopes, &c.Scopes)
	c.Metadata = json.RawMessage(meta)
	return &c, nil
}

func normalizeJSON(raw json.RawMessage) string {
	if len(raw) == 0 {
		return "{}"
	}
	return string(raw)
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505" // unique_violation
	}
	return false
}
