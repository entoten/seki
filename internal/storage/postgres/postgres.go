package postgres

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/Monet/seki/internal/config"
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
// Pool settings from the config are applied to the underlying pgxpool.
func New(ctx context.Context, cfg config.DatabaseConfig) (*Store, error) {
	poolCfg, err := pgxpool.ParseConfig(cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("postgres: parse config: %w", err)
	}
	// Apply connection pool settings.
	if cfg.MaxOpenConns > 0 && cfg.MaxOpenConns <= math.MaxInt32 {
		poolCfg.MaxConns = int32(cfg.MaxOpenConns) // #nosec G115 -- bounds checked
	}
	if cfg.MaxIdleConns > 0 && cfg.MaxIdleConns <= math.MaxInt32 {
		poolCfg.MinConns = int32(cfg.MaxIdleConns) // #nosec G115 -- bounds checked
	}
	if d, parseErr := time.ParseDuration(cfg.ConnMaxLifetime); parseErr == nil {
		poolCfg.MaxConnLifetime = d
	}
	if d, parseErr := time.ParseDuration(cfg.ConnMaxIdleTime); parseErr == nil {
		poolCfg.MaxConnIdleTime = d
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
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
		"migrations/003_refresh_tokens.up.sql",
		"migrations/004_credentials_webauthn.up.sql",
		"migrations/005_organizations.up.sql",
		"migrations/006_verification_tokens.up.sql",
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
		`INSERT INTO users (id, email, display_name, disabled, email_verified, metadata, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		user.ID, user.Email, user.DisplayName, user.Disabled, user.EmailVerified, meta, now, now,
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
		`SELECT id, email, display_name, disabled, email_verified, metadata, created_at, updated_at
		 FROM users WHERE id = $1`, id)
	return scanUser(row)
}

func (s *Store) GetUserByEmail(ctx context.Context, email string) (*storage.User, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, email, display_name, disabled, email_verified, metadata, created_at, updated_at
		 FROM users WHERE email = $1`, email)
	return scanUser(row)
}

func (s *Store) UpdateUser(ctx context.Context, user *storage.User) error {
	meta := normalizeJSON(user.Metadata)
	now := time.Now().UTC()
	ct, err := s.pool.Exec(ctx,
		`UPDATE users SET email = $1, display_name = $2, disabled = $3, email_verified = $4, metadata = $5, updated_at = $6
		 WHERE id = $7`,
		user.Email, user.DisplayName, user.Disabled, user.EmailVerified, meta, now, user.ID,
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
			`SELECT id, email, display_name, disabled, email_verified, metadata, created_at, updated_at
			 FROM users WHERE id > $1 ORDER BY id ASC LIMIT $2`,
			opts.Cursor, limit+1,
		)
	} else {
		rows, err = s.pool.Query(ctx,
			`SELECT id, email, display_name, disabled, email_verified, metadata, created_at, updated_at
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

func (s *Store) ListSessionsByUserID(ctx context.Context, userID string) ([]*storage.Session, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, user_id, client_id, ip_address, user_agent, metadata, created_at, expires_at, last_active_at, absolute_expires_at
		 FROM sessions WHERE user_id = $1 ORDER BY created_at ASC`, userID)
	if err != nil {
		return nil, fmt.Errorf("postgres: list sessions by user: %w", err)
	}
	defer rows.Close()

	var sessions []*storage.Session
	for rows.Next() {
		var sess storage.Session
		var meta []byte
		err := rows.Scan(&sess.ID, &sess.UserID, &sess.ClientID, &sess.IPAddress, &sess.UserAgent, &meta, &sess.CreatedAt, &sess.ExpiresAt, &sess.LastActiveAt, &sess.AbsoluteExpiresAt)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan session row: %w", err)
		}
		sess.Metadata = json.RawMessage(meta)
		sessions = append(sessions, &sess)
	}
	return sessions, rows.Err()
}

func (s *Store) CountSessionsByUserID(ctx context.Context, userID string) (int64, error) {
	var count int64
	err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM sessions WHERE user_id = $1`, userID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("postgres: count sessions by user: %w", err)
	}
	return count, nil
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
// RefreshTokenStore
// ---------------------------------------------------------------------------

func (s *Store) CreateRefreshToken(ctx context.Context, token *storage.RefreshToken) error {
	scopes, _ := json.Marshal(token.Scopes)
	_, err := s.pool.Exec(ctx,
		`INSERT INTO refresh_tokens (id, token_hash, client_id, user_id, scopes, family, expires_at, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		token.ID, token.TokenHash, token.ClientID, token.UserID,
		string(scopes), token.Family,
		token.ExpiresAt.UTC(), token.CreatedAt.UTC(),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return storage.ErrAlreadyExists
		}
		return fmt.Errorf("postgres: create refresh token: %w", err)
	}
	return nil
}

func (s *Store) GetRefreshTokenByHash(ctx context.Context, hash string) (*storage.RefreshToken, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, token_hash, client_id, user_id, scopes, family, expires_at, created_at
		 FROM refresh_tokens WHERE token_hash = $1`, hash)
	var rt storage.RefreshToken
	var scopes []byte
	err := row.Scan(&rt.ID, &rt.TokenHash, &rt.ClientID, &rt.UserID, &scopes, &rt.Family, &rt.ExpiresAt, &rt.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("postgres: scan refresh token: %w", err)
	}
	_ = json.Unmarshal(scopes, &rt.Scopes)
	return &rt, nil
}

func (s *Store) DeleteRefreshToken(ctx context.Context, id string) error {
	ct, err := s.pool.Exec(ctx, `DELETE FROM refresh_tokens WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("postgres: delete refresh token: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *Store) DeleteRefreshTokensByFamily(ctx context.Context, family string) (int64, error) {
	ct, err := s.pool.Exec(ctx, `DELETE FROM refresh_tokens WHERE family = $1`, family)
	if err != nil {
		return 0, fmt.Errorf("postgres: delete refresh tokens by family: %w", err)
	}
	return ct.RowsAffected(), nil
}

func (s *Store) DeleteRefreshTokensByUserID(ctx context.Context, userID string) (int64, error) {
	ct, err := s.pool.Exec(ctx, `DELETE FROM refresh_tokens WHERE user_id = $1`, userID)
	if err != nil {
		return 0, fmt.Errorf("postgres: delete refresh tokens by user: %w", err)
	}
	return ct.RowsAffected(), nil
}

// ---------------------------------------------------------------------------
// CredentialStore
// ---------------------------------------------------------------------------

func (s *Store) CreateCredential(ctx context.Context, cred *storage.Credential) error {
	now := cred.CreatedAt.UTC()
	_, err := s.pool.Exec(ctx,
		`INSERT INTO credentials (id, user_id, type, credential_id, public_key, attestation_type, aaguid, sign_count, display_name, last_used_at, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		cred.ID, cred.UserID, cred.Type, cred.CredentialID, cred.PublicKey,
		cred.AttestationType, cred.AAGUID, cred.SignCount, cred.DisplayName,
		cred.LastUsedAt, now,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return storage.ErrAlreadyExists
		}
		return fmt.Errorf("postgres: create credential: %w", err)
	}
	return nil
}

func (s *Store) GetCredential(ctx context.Context, id string) (*storage.Credential, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, user_id, type, credential_id, public_key, attestation_type, aaguid, sign_count, display_name, last_used_at, created_at
		 FROM credentials WHERE id = $1`, id)
	return scanCredentialPgx(row)
}

func (s *Store) GetCredentialByCredentialID(ctx context.Context, credentialID []byte) (*storage.Credential, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, user_id, type, credential_id, public_key, attestation_type, aaguid, sign_count, display_name, last_used_at, created_at
		 FROM credentials WHERE credential_id = $1`, credentialID)
	return scanCredentialPgx(row)
}

func (s *Store) GetCredentialsByUserAndType(ctx context.Context, userID string, credType string) ([]*storage.Credential, error) {
	return s.ListCredentialsByUser(ctx, userID, credType)
}

func (s *Store) ListCredentialsByUser(ctx context.Context, userID string, credType string) ([]*storage.Credential, error) {
	var rows pgx.Rows
	var err error
	if credType != "" {
		rows, err = s.pool.Query(ctx,
			`SELECT id, user_id, type, credential_id, public_key, attestation_type, aaguid, sign_count, display_name, last_used_at, created_at
			 FROM credentials WHERE user_id = $1 AND type = $2 ORDER BY created_at ASC`,
			userID, credType,
		)
	} else {
		rows, err = s.pool.Query(ctx,
			`SELECT id, user_id, type, credential_id, public_key, attestation_type, aaguid, sign_count, display_name, last_used_at, created_at
			 FROM credentials WHERE user_id = $1 ORDER BY created_at ASC`,
			userID,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: list credentials: %w", err)
	}
	defer rows.Close()

	var creds []*storage.Credential
	for rows.Next() {
		var c storage.Credential
		err := rows.Scan(&c.ID, &c.UserID, &c.Type, &c.CredentialID, &c.PublicKey,
			&c.AttestationType, &c.AAGUID, &c.SignCount, &c.DisplayName,
			&c.LastUsedAt, &c.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan credential: %w", err)
		}
		creds = append(creds, &c)
	}
	return creds, rows.Err()
}

func (s *Store) UpdateCredential(ctx context.Context, cred *storage.Credential) error {
	now := time.Now().UTC()
	ct, err := s.pool.Exec(ctx,
		`UPDATE credentials SET type = $1, credential_id = $2, public_key = $3, attestation_type = $4, aaguid = $5, sign_count = $6, display_name = $7, last_used_at = $8, updated_at = $9 WHERE id = $10`,
		cred.Type, cred.CredentialID, cred.PublicKey,
		cred.AttestationType, cred.AAGUID, cred.SignCount,
		cred.DisplayName, cred.LastUsedAt, now, cred.ID,
	)
	if err != nil {
		return fmt.Errorf("postgres: update credential: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *Store) UpdateCredentialSignCount(ctx context.Context, id string, signCount uint32, lastUsedAt time.Time) error {
	ct, err := s.pool.Exec(ctx,
		`UPDATE credentials SET sign_count = $1, last_used_at = $2 WHERE id = $3`,
		signCount, lastUsedAt.UTC(), id,
	)
	if err != nil {
		return fmt.Errorf("postgres: update credential sign count: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *Store) DeleteCredential(ctx context.Context, id string) error {
	ct, err := s.pool.Exec(ctx, `DELETE FROM credentials WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("postgres: delete credential: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *Store) DeleteCredentialsByUserAndType(ctx context.Context, userID string, credType string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM credentials WHERE user_id = $1 AND type = $2`, userID, credType)
	if err != nil {
		return fmt.Errorf("postgres: delete credentials by user and type: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// OrgStore
// ---------------------------------------------------------------------------

func (s *Store) CreateOrg(ctx context.Context, org *storage.Organization) error {
	domains, _ := json.Marshal(org.Domains)
	meta := normalizeJSON(org.Metadata)
	now := org.CreatedAt.UTC()
	_, err := s.pool.Exec(ctx,
		`INSERT INTO organizations (id, slug, name, domains, metadata, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		org.ID, org.Slug, org.Name, string(domains), meta, now, now,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return storage.ErrAlreadyExists
		}
		return fmt.Errorf("postgres: create org: %w", err)
	}
	return nil
}

func (s *Store) GetOrg(ctx context.Context, id string) (*storage.Organization, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, slug, name, domains, metadata, created_at, updated_at
		 FROM organizations WHERE id = $1`, id)
	return scanOrgPgx(row)
}

func (s *Store) GetOrgBySlug(ctx context.Context, slug string) (*storage.Organization, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, slug, name, domains, metadata, created_at, updated_at
		 FROM organizations WHERE slug = $1`, slug)
	return scanOrgPgx(row)
}

func (s *Store) UpdateOrg(ctx context.Context, org *storage.Organization) error {
	domains, _ := json.Marshal(org.Domains)
	meta := normalizeJSON(org.Metadata)
	now := time.Now().UTC()
	ct, err := s.pool.Exec(ctx,
		`UPDATE organizations SET slug = $1, name = $2, domains = $3, metadata = $4, updated_at = $5
		 WHERE id = $6`,
		org.Slug, org.Name, string(domains), meta, now, org.ID,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return storage.ErrAlreadyExists
		}
		return fmt.Errorf("postgres: update org: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *Store) DeleteOrg(ctx context.Context, id string) error {
	ct, err := s.pool.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("postgres: delete org: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *Store) ListOrgs(ctx context.Context, opts storage.ListOptions) ([]*storage.Organization, string, error) {
	limit := opts.Limit
	if limit <= 0 {
		limit = defaultLimit
	}
	var rows pgx.Rows
	var err error
	if opts.Cursor != "" {
		rows, err = s.pool.Query(ctx,
			`SELECT id, slug, name, domains, metadata, created_at, updated_at
			 FROM organizations WHERE id > $1 ORDER BY id ASC LIMIT $2`,
			opts.Cursor, limit+1,
		)
	} else {
		rows, err = s.pool.Query(ctx,
			`SELECT id, slug, name, domains, metadata, created_at, updated_at
			 FROM organizations ORDER BY id ASC LIMIT $1`,
			limit+1,
		)
	}
	if err != nil {
		return nil, "", fmt.Errorf("postgres: list orgs: %w", err)
	}
	defer rows.Close()

	var orgs []*storage.Organization
	for rows.Next() {
		o, err := scanOrgPgxRows(rows)
		if err != nil {
			return nil, "", err
		}
		orgs = append(orgs, o)
	}
	if err := rows.Err(); err != nil {
		return nil, "", fmt.Errorf("postgres: list orgs rows: %w", err)
	}

	var nextCursor string
	if len(orgs) > limit {
		nextCursor = orgs[limit-1].ID
		orgs = orgs[:limit]
	}
	return orgs, nextCursor, nil
}

func (s *Store) AddMember(ctx context.Context, member *storage.OrgMember) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO org_members (org_id, user_id, role, joined_at)
		 VALUES ($1, $2, $3, $4)`,
		member.OrgID, member.UserID, member.Role, member.JoinedAt.UTC(),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return storage.ErrAlreadyExists
		}
		return fmt.Errorf("postgres: add member: %w", err)
	}
	return nil
}

func (s *Store) RemoveMember(ctx context.Context, orgID, userID string) error {
	ct, err := s.pool.Exec(ctx,
		`DELETE FROM org_members WHERE org_id = $1 AND user_id = $2`, orgID, userID)
	if err != nil {
		return fmt.Errorf("postgres: remove member: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *Store) ListMembers(ctx context.Context, orgID string) ([]*storage.OrgMember, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT org_id, user_id, role, joined_at
		 FROM org_members WHERE org_id = $1 ORDER BY joined_at ASC`, orgID)
	if err != nil {
		return nil, fmt.Errorf("postgres: list members: %w", err)
	}
	defer rows.Close()

	var members []*storage.OrgMember
	for rows.Next() {
		var m storage.OrgMember
		err := rows.Scan(&m.OrgID, &m.UserID, &m.Role, &m.JoinedAt)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan org member: %w", err)
		}
		members = append(members, &m)
	}
	return members, rows.Err()
}

func (s *Store) GetMembership(ctx context.Context, orgID, userID string) (*storage.OrgMember, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT org_id, user_id, role, joined_at
		 FROM org_members WHERE org_id = $1 AND user_id = $2`, orgID, userID)
	var m storage.OrgMember
	err := row.Scan(&m.OrgID, &m.UserID, &m.Role, &m.JoinedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("postgres: scan membership: %w", err)
	}
	return &m, nil
}

func (s *Store) UpdateMemberRole(ctx context.Context, orgID, userID, role string) error {
	ct, err := s.pool.Exec(ctx,
		`UPDATE org_members SET role = $1 WHERE org_id = $2 AND user_id = $3`,
		role, orgID, userID,
	)
	if err != nil {
		return fmt.Errorf("postgres: update member role: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

// ---------------------------------------------------------------------------
// RoleStore
// ---------------------------------------------------------------------------

func (s *Store) CreateRole(ctx context.Context, role *storage.Role) error {
	perms, _ := json.Marshal(role.Permissions)
	now := role.CreatedAt.UTC()
	_, err := s.pool.Exec(ctx,
		`INSERT INTO roles (id, org_id, name, permissions, created_at)
		 VALUES ($1, $2, $3, $4, $5)`,
		role.ID, role.OrgID, role.Name, string(perms), now,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return storage.ErrAlreadyExists
		}
		return fmt.Errorf("postgres: create role: %w", err)
	}
	return nil
}

func (s *Store) GetRole(ctx context.Context, id string) (*storage.Role, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, org_id, name, permissions, created_at
		 FROM roles WHERE id = $1`, id)
	return scanRolePgx(row)
}

func (s *Store) GetRoleByName(ctx context.Context, orgID, name string) (*storage.Role, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, org_id, name, permissions, created_at
		 FROM roles WHERE org_id = $1 AND name = $2`, orgID, name)
	return scanRolePgx(row)
}

func (s *Store) ListRoles(ctx context.Context, orgID string) ([]*storage.Role, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, org_id, name, permissions, created_at
		 FROM roles WHERE org_id = $1 ORDER BY name ASC`, orgID)
	if err != nil {
		return nil, fmt.Errorf("postgres: list roles: %w", err)
	}
	defer rows.Close()

	var roles []*storage.Role
	for rows.Next() {
		var r storage.Role
		var perms []byte
		err := rows.Scan(&r.ID, &r.OrgID, &r.Name, &perms, &r.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan role: %w", err)
		}
		_ = json.Unmarshal(perms, &r.Permissions)
		roles = append(roles, &r)
	}
	return roles, rows.Err()
}

func (s *Store) UpdateRole(ctx context.Context, role *storage.Role) error {
	perms, _ := json.Marshal(role.Permissions)
	ct, err := s.pool.Exec(ctx,
		`UPDATE roles SET name = $1, permissions = $2 WHERE id = $3`,
		role.Name, string(perms), role.ID,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return storage.ErrAlreadyExists
		}
		return fmt.Errorf("postgres: update role: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *Store) DeleteRole(ctx context.Context, id string) error {
	ct, err := s.pool.Exec(ctx, `DELETE FROM roles WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("postgres: delete role: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func scanOrgPgx(row pgx.Row) (*storage.Organization, error) {
	var o storage.Organization
	var domains, meta []byte
	err := row.Scan(&o.ID, &o.Slug, &o.Name, &domains, &meta, &o.CreatedAt, &o.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("postgres: scan org: %w", err)
	}
	_ = json.Unmarshal(domains, &o.Domains)
	o.Metadata = json.RawMessage(meta)
	return &o, nil
}

func scanOrgPgxRows(rows pgx.Rows) (*storage.Organization, error) {
	var o storage.Organization
	var domains, meta []byte
	err := rows.Scan(&o.ID, &o.Slug, &o.Name, &domains, &meta, &o.CreatedAt, &o.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("postgres: scan org: %w", err)
	}
	_ = json.Unmarshal(domains, &o.Domains)
	o.Metadata = json.RawMessage(meta)
	return &o, nil
}

func scanRolePgx(row pgx.Row) (*storage.Role, error) {
	var r storage.Role
	var perms []byte
	err := row.Scan(&r.ID, &r.OrgID, &r.Name, &perms, &r.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("postgres: scan role: %w", err)
	}
	_ = json.Unmarshal(perms, &r.Permissions)
	return &r, nil
}

func scanCredentialPgx(row pgx.Row) (*storage.Credential, error) {
	var c storage.Credential
	err := row.Scan(&c.ID, &c.UserID, &c.Type, &c.CredentialID, &c.PublicKey,
		&c.AttestationType, &c.AAGUID, &c.SignCount, &c.DisplayName,
		&c.LastUsedAt, &c.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("postgres: scan credential: %w", err)
	}
	return &c, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func scanUser(row pgx.Row) (*storage.User, error) {
	var u storage.User
	var meta []byte
	err := row.Scan(&u.ID, &u.Email, &u.DisplayName, &u.Disabled, &u.EmailVerified, &meta, &u.CreatedAt, &u.UpdatedAt)
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
	err := rows.Scan(&u.ID, &u.Email, &u.DisplayName, &u.Disabled, &u.EmailVerified, &meta, &u.CreatedAt, &u.UpdatedAt)
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

// ---------------------------------------------------------------------------
// VerificationTokenStore
// ---------------------------------------------------------------------------

func (s *Store) CreateVerificationToken(ctx context.Context, token *storage.VerificationToken) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO verification_tokens (id, user_id, type, token_hash, expires_at, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		token.ID, token.UserID, token.Type, token.TokenHash,
		token.ExpiresAt.UTC(), token.CreatedAt.UTC(),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return storage.ErrAlreadyExists
		}
		return fmt.Errorf("postgres: create verification token: %w", err)
	}
	return nil
}

func (s *Store) GetVerificationTokenByHash(ctx context.Context, hash string) (*storage.VerificationToken, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, user_id, type, token_hash, expires_at, created_at, used_at
		 FROM verification_tokens WHERE token_hash = $1`, hash)
	var t storage.VerificationToken
	err := row.Scan(&t.ID, &t.UserID, &t.Type, &t.TokenHash, &t.ExpiresAt, &t.CreatedAt, &t.UsedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("postgres: get verification token: %w", err)
	}
	return &t, nil
}

func (s *Store) MarkTokenUsed(ctx context.Context, id string) error {
	now := time.Now().UTC()
	ct, err := s.pool.Exec(ctx,
		`UPDATE verification_tokens SET used_at = $1 WHERE id = $2`, now, id)
	if err != nil {
		return fmt.Errorf("postgres: mark token used: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *Store) DeleteExpiredTokens(ctx context.Context) (int64, error) {
	now := time.Now().UTC()
	ct, err := s.pool.Exec(ctx,
		`DELETE FROM verification_tokens WHERE expires_at < $1 AND used_at IS NULL`, now)
	if err != nil {
		return 0, fmt.Errorf("postgres: delete expired tokens: %w", err)
	}
	return ct.RowsAffected(), nil
}
