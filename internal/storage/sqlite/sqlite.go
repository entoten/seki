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

// Migrate runs all embedded up migrations against the database in order.
func (s *Store) Migrate() error {
	if err := RunMigrations(s.db); err != nil {
		return fmt.Errorf("sqlite: %w", err)
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
		`INSERT INTO users (id, email, display_name, disabled, email_verified, metadata, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		user.ID, user.Email, user.DisplayName, boolToInt(user.Disabled), boolToInt(user.EmailVerified), meta, now, now,
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
		`SELECT id, email, display_name, disabled, email_verified, metadata, created_at, updated_at
		 FROM users WHERE id = ?`, id)
	return scanUser(row)
}

func (s *Store) GetUserByEmail(ctx context.Context, email string) (*storage.User, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, email, display_name, disabled, email_verified, metadata, created_at, updated_at
		 FROM users WHERE email = ?`, email)
	return scanUser(row)
}

func (s *Store) UpdateUser(ctx context.Context, user *storage.User) error {
	meta := normalizeJSON(user.Metadata)
	now := timeStr(time.Now().UTC())
	res, err := s.db.ExecContext(ctx,
		`UPDATE users SET email = ?, display_name = ?, disabled = ?, email_verified = ?, metadata = ?, updated_at = ?
		 WHERE id = ?`,
		user.Email, user.DisplayName, boolToInt(user.Disabled), boolToInt(user.EmailVerified), meta, now, user.ID,
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
			`SELECT id, email, display_name, disabled, email_verified, metadata, created_at, updated_at
			 FROM users WHERE id > ? ORDER BY id ASC LIMIT ?`,
			opts.Cursor, limit+1,
		)
	} else {
		rows, err = s.db.QueryContext(ctx,
			`SELECT id, email, display_name, disabled, email_verified, metadata, created_at, updated_at
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
		`INSERT INTO sessions (id, user_id, client_id, ip_address, user_agent, metadata, created_at, expires_at, last_active_at, absolute_expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		session.ID, session.UserID, session.ClientID,
		session.IPAddress, session.UserAgent, meta,
		timeStr(session.CreatedAt), timeStr(session.ExpiresAt),
		timeStr(session.LastActiveAt), timeStr(session.AbsoluteExpiresAt),
	)
	if err != nil {
		return fmt.Errorf("sqlite: create session: %w", err)
	}
	return nil
}

func (s *Store) GetSession(ctx context.Context, id string) (*storage.Session, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, user_id, client_id, ip_address, user_agent, metadata, created_at, expires_at, last_active_at, absolute_expires_at
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
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < ? OR absolute_expires_at < ?`, now, now)
	if err != nil {
		return 0, fmt.Errorf("sqlite: delete expired sessions: %w", err)
	}
	return res.RowsAffected()
}

func (s *Store) UpdateSessionActivity(ctx context.Context, id string, lastActive time.Time) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET last_active_at = ? WHERE id = ?`,
		timeStr(lastActive), id,
	)
	if err != nil {
		return fmt.Errorf("sqlite: update session activity: %w", err)
	}
	return checkRowsAffected(res, "session")
}

func (s *Store) DeleteSessionsByUserID(ctx context.Context, userID string) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, userID)
	if err != nil {
		return 0, fmt.Errorf("sqlite: delete sessions by user: %w", err)
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
	if !opts.From.IsZero() {
		query += ` AND created_at >= ?`
		args = append(args, timeStr(opts.From))
	}
	if !opts.To.IsZero() {
		query += ` AND created_at < ?`
		args = append(args, timeStr(opts.To))
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
// AuthCodeStore
// ---------------------------------------------------------------------------

func (s *Store) CreateAuthCode(ctx context.Context, code *storage.AuthCode) error {
	scopes, _ := json.Marshal(code.Scopes)
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO authorization_codes (code, client_id, user_id, redirect_uri, scopes, code_challenge, code_challenge_method, nonce, state, expires_at, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		code.Code, code.ClientID, code.UserID, code.RedirectURI,
		string(scopes), code.CodeChallenge, code.CodeChallengeMethod,
		code.Nonce, code.State,
		timeStr(code.ExpiresAt), timeStr(code.CreatedAt),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return storage.ErrAlreadyExists
		}
		return fmt.Errorf("sqlite: create auth code: %w", err)
	}
	return nil
}

func (s *Store) GetAuthCode(ctx context.Context, code string) (*storage.AuthCode, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT code, client_id, user_id, redirect_uri, scopes, code_challenge, code_challenge_method, nonce, state, expires_at, created_at
		 FROM authorization_codes WHERE code = ?`, code)
	var ac storage.AuthCode
	var scopes string
	var expiresAt, createdAt string
	err := row.Scan(&ac.Code, &ac.ClientID, &ac.UserID, &ac.RedirectURI, &scopes, &ac.CodeChallenge, &ac.CodeChallengeMethod, &ac.Nonce, &ac.State, &expiresAt, &createdAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("sqlite: scan auth code: %w", err)
	}
	_ = json.Unmarshal([]byte(scopes), &ac.Scopes)
	ac.ExpiresAt, _ = time.Parse(time.RFC3339, expiresAt)
	ac.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	return &ac, nil
}

func (s *Store) DeleteAuthCode(ctx context.Context, code string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM authorization_codes WHERE code = ?`, code)
	if err != nil {
		return fmt.Errorf("sqlite: delete auth code: %w", err)
	}
	return checkRowsAffected(res, "authorization code")
}

// ---------------------------------------------------------------------------
// RefreshTokenStore
// ---------------------------------------------------------------------------

func (s *Store) CreateRefreshToken(ctx context.Context, token *storage.RefreshToken) error {
	scopes, _ := json.Marshal(token.Scopes)
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO refresh_tokens (id, token_hash, client_id, user_id, scopes, family, expires_at, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		token.ID, token.TokenHash, token.ClientID, token.UserID,
		string(scopes), token.Family,
		timeStr(token.ExpiresAt), timeStr(token.CreatedAt),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return storage.ErrAlreadyExists
		}
		return fmt.Errorf("sqlite: create refresh token: %w", err)
	}
	return nil
}

func (s *Store) GetRefreshTokenByHash(ctx context.Context, hash string) (*storage.RefreshToken, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, token_hash, client_id, user_id, scopes, family, expires_at, created_at
		 FROM refresh_tokens WHERE token_hash = ?`, hash)
	var rt storage.RefreshToken
	var scopes string
	var expiresAt, createdAt string
	err := row.Scan(&rt.ID, &rt.TokenHash, &rt.ClientID, &rt.UserID, &scopes, &rt.Family, &expiresAt, &createdAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("sqlite: scan refresh token: %w", err)
	}
	_ = json.Unmarshal([]byte(scopes), &rt.Scopes)
	rt.ExpiresAt, _ = time.Parse(time.RFC3339, expiresAt)
	rt.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	return &rt, nil
}

func (s *Store) DeleteRefreshToken(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("sqlite: delete refresh token: %w", err)
	}
	return checkRowsAffected(res, "refresh token")
}

func (s *Store) DeleteRefreshTokensByFamily(ctx context.Context, family string) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE family = ?`, family)
	if err != nil {
		return 0, fmt.Errorf("sqlite: delete refresh tokens by family: %w", err)
	}
	return res.RowsAffected()
}

func (s *Store) DeleteRefreshTokensByUserID(ctx context.Context, userID string) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE user_id = ?`, userID)
	if err != nil {
		return 0, fmt.Errorf("sqlite: delete refresh tokens by user: %w", err)
	}
	return res.RowsAffected()
}

// ---------------------------------------------------------------------------
// CredentialStore
// ---------------------------------------------------------------------------

// credentialColumns is the column list used for credential SELECT queries.
const credentialColumns = `id, user_id, type, secret, metadata, credential_id, public_key, attestation_type, aaguid, sign_count, display_name, last_used_at, created_at, updated_at`

func (s *Store) CreateCredential(ctx context.Context, cred *storage.Credential) error {
	meta := normalizeJSON(cred.Metadata)
	now := timeStr(cred.CreatedAt)
	var lastUsedStr *string
	if cred.LastUsedAt != nil {
		v := timeStr(*cred.LastUsedAt)
		lastUsedStr = &v
	}
	secret := cred.Secret
	if secret == nil {
		secret = []byte{}
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO credentials (id, user_id, type, secret, metadata, credential_id, public_key, attestation_type, aaguid, sign_count, display_name, last_used_at, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		cred.ID, cred.UserID, cred.Type, secret, meta,
		cred.CredentialID, cred.PublicKey,
		cred.AttestationType, cred.AAGUID, cred.SignCount, cred.DisplayName,
		lastUsedStr, now, now,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return storage.ErrAlreadyExists
		}
		return fmt.Errorf("sqlite: create credential: %w", err)
	}
	return nil
}

func (s *Store) GetCredential(ctx context.Context, id string) (*storage.Credential, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+credentialColumns+` FROM credentials WHERE id = ?`, id)
	return scanCredentialRow(row)
}

func (s *Store) GetCredentialByCredentialID(ctx context.Context, credentialID []byte) (*storage.Credential, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+credentialColumns+` FROM credentials WHERE credential_id = ?`, credentialID)
	return scanCredentialRow(row)
}

func (s *Store) GetCredentialsByUserAndType(ctx context.Context, userID string, credType string) ([]*storage.Credential, error) {
	return s.ListCredentialsByUser(ctx, userID, credType)
}

func (s *Store) ListCredentialsByUser(ctx context.Context, userID string, credType string) ([]*storage.Credential, error) {
	var rows *sql.Rows
	var err error
	if credType != "" {
		rows, err = s.db.QueryContext(ctx,
			`SELECT `+credentialColumns+` FROM credentials WHERE user_id = ? AND type = ? ORDER BY created_at ASC`,
			userID, credType,
		)
	} else {
		rows, err = s.db.QueryContext(ctx,
			`SELECT `+credentialColumns+` FROM credentials WHERE user_id = ? ORDER BY created_at ASC`,
			userID,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("sqlite: list credentials: %w", err)
	}
	defer rows.Close()

	var creds []*storage.Credential
	for rows.Next() {
		c, err := scanCredentialRow(rows)
		if err != nil {
			return nil, err
		}
		creds = append(creds, c)
	}
	return creds, rows.Err()
}

func (s *Store) UpdateCredential(ctx context.Context, cred *storage.Credential) error {
	meta := normalizeJSON(cred.Metadata)
	now := timeStr(time.Now().UTC())
	var lastUsedStr *string
	if cred.LastUsedAt != nil {
		v := timeStr(*cred.LastUsedAt)
		lastUsedStr = &v
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE credentials SET secret = ?, metadata = ?, credential_id = ?, public_key = ?, attestation_type = ?, aaguid = ?, sign_count = ?, display_name = ?, last_used_at = ?, updated_at = ? WHERE id = ?`,
		cred.Secret, meta, cred.CredentialID, cred.PublicKey,
		cred.AttestationType, cred.AAGUID, cred.SignCount,
		cred.DisplayName, lastUsedStr, now, cred.ID,
	)
	if err != nil {
		return fmt.Errorf("sqlite: update credential: %w", err)
	}
	return checkRowsAffected(res, "credential")
}

func (s *Store) UpdateCredentialSignCount(ctx context.Context, id string, signCount uint32, lastUsedAt time.Time) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE credentials SET sign_count = ?, last_used_at = ? WHERE id = ?`,
		signCount, timeStr(lastUsedAt), id,
	)
	if err != nil {
		return fmt.Errorf("sqlite: update credential sign count: %w", err)
	}
	return checkRowsAffected(res, "credential")
}

func (s *Store) DeleteCredential(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM credentials WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("sqlite: delete credential: %w", err)
	}
	return checkRowsAffected(res, "credential")
}

func (s *Store) DeleteCredentialsByUserAndType(ctx context.Context, userID string, credType string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM credentials WHERE user_id = ? AND type = ?`, userID, credType)
	if err != nil {
		return fmt.Errorf("sqlite: delete credentials by user and type: %w", err)
	}
	return nil
}

func scanCredentialRow(row scanner) (*storage.Credential, error) {
	var c storage.Credential
	var meta string
	var lastUsedStr *string
	var createdAt, updatedAt string
	err := row.Scan(&c.ID, &c.UserID, &c.Type, &c.Secret, &meta,
		&c.CredentialID, &c.PublicKey,
		&c.AttestationType, &c.AAGUID, &c.SignCount, &c.DisplayName,
		&lastUsedStr, &createdAt, &updatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("sqlite: scan credential: %w", err)
	}
	c.Metadata = json.RawMessage(meta)
	c.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	c.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
	if lastUsedStr != nil {
		t, _ := time.Parse(time.RFC3339, *lastUsedStr)
		c.LastUsedAt = &t
	}
	return &c, nil
}

// ---------------------------------------------------------------------------
// OrgStore
// ---------------------------------------------------------------------------

func (s *Store) CreateOrg(ctx context.Context, org *storage.Organization) error {
	domains, _ := json.Marshal(org.Domains)
	meta := normalizeJSON(org.Metadata)
	now := timeStr(org.CreatedAt)
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO organizations (id, slug, name, domains, metadata, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		org.ID, org.Slug, org.Name, string(domains), meta, now, now,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return storage.ErrAlreadyExists
		}
		return fmt.Errorf("sqlite: create org: %w", err)
	}
	return nil
}

func (s *Store) GetOrg(ctx context.Context, id string) (*storage.Organization, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, slug, name, domains, metadata, created_at, updated_at
		 FROM organizations WHERE id = ?`, id)
	return scanOrg(row)
}

func (s *Store) GetOrgBySlug(ctx context.Context, slug string) (*storage.Organization, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, slug, name, domains, metadata, created_at, updated_at
		 FROM organizations WHERE slug = ?`, slug)
	return scanOrg(row)
}

func (s *Store) UpdateOrg(ctx context.Context, org *storage.Organization) error {
	domains, _ := json.Marshal(org.Domains)
	meta := normalizeJSON(org.Metadata)
	now := timeStr(time.Now().UTC())
	res, err := s.db.ExecContext(ctx,
		`UPDATE organizations SET slug = ?, name = ?, domains = ?, metadata = ?, updated_at = ?
		 WHERE id = ?`,
		org.Slug, org.Name, string(domains), meta, now, org.ID,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return storage.ErrAlreadyExists
		}
		return fmt.Errorf("sqlite: update org: %w", err)
	}
	return checkRowsAffected(res, "organization")
}

func (s *Store) DeleteOrg(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM organizations WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("sqlite: delete org: %w", err)
	}
	return checkRowsAffected(res, "organization")
}

func (s *Store) ListOrgs(ctx context.Context, opts storage.ListOptions) ([]*storage.Organization, string, error) {
	limit := opts.Limit
	if limit <= 0 {
		limit = defaultLimit
	}
	var rows *sql.Rows
	var err error
	if opts.Cursor != "" {
		rows, err = s.db.QueryContext(ctx,
			`SELECT id, slug, name, domains, metadata, created_at, updated_at
			 FROM organizations WHERE id > ? ORDER BY id ASC LIMIT ?`,
			opts.Cursor, limit+1,
		)
	} else {
		rows, err = s.db.QueryContext(ctx,
			`SELECT id, slug, name, domains, metadata, created_at, updated_at
			 FROM organizations ORDER BY id ASC LIMIT ?`,
			limit+1,
		)
	}
	if err != nil {
		return nil, "", fmt.Errorf("sqlite: list orgs: %w", err)
	}
	defer rows.Close()

	var orgs []*storage.Organization
	for rows.Next() {
		o, err := scanOrg(rows)
		if err != nil {
			return nil, "", err
		}
		orgs = append(orgs, o)
	}
	if err := rows.Err(); err != nil {
		return nil, "", fmt.Errorf("sqlite: list orgs rows: %w", err)
	}

	var nextCursor string
	if len(orgs) > limit {
		nextCursor = orgs[limit-1].ID
		orgs = orgs[:limit]
	}
	return orgs, nextCursor, nil
}

func (s *Store) AddMember(ctx context.Context, member *storage.OrgMember) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO org_members (org_id, user_id, role, joined_at)
		 VALUES (?, ?, ?, ?)`,
		member.OrgID, member.UserID, member.Role, timeStr(member.JoinedAt),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return storage.ErrAlreadyExists
		}
		return fmt.Errorf("sqlite: add member: %w", err)
	}
	return nil
}

func (s *Store) RemoveMember(ctx context.Context, orgID, userID string) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM org_members WHERE org_id = ? AND user_id = ?`, orgID, userID)
	if err != nil {
		return fmt.Errorf("sqlite: remove member: %w", err)
	}
	return checkRowsAffected(res, "org member")
}

func (s *Store) ListMembers(ctx context.Context, orgID string) ([]*storage.OrgMember, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT org_id, user_id, role, joined_at
		 FROM org_members WHERE org_id = ? ORDER BY joined_at ASC`, orgID)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list members: %w", err)
	}
	defer rows.Close()

	var members []*storage.OrgMember
	for rows.Next() {
		m, err := scanMember(rows)
		if err != nil {
			return nil, err
		}
		members = append(members, m)
	}
	return members, rows.Err()
}

func (s *Store) GetMembership(ctx context.Context, orgID, userID string) (*storage.OrgMember, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT org_id, user_id, role, joined_at
		 FROM org_members WHERE org_id = ? AND user_id = ?`, orgID, userID)
	return scanMember(row)
}

func (s *Store) UpdateMemberRole(ctx context.Context, orgID, userID, role string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE org_members SET role = ? WHERE org_id = ? AND user_id = ?`,
		role, orgID, userID,
	)
	if err != nil {
		return fmt.Errorf("sqlite: update member role: %w", err)
	}
	return checkRowsAffected(res, "org member")
}

// ---------------------------------------------------------------------------
// RoleStore
// ---------------------------------------------------------------------------

func (s *Store) CreateRole(ctx context.Context, role *storage.Role) error {
	perms, _ := json.Marshal(role.Permissions)
	now := timeStr(role.CreatedAt)
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO roles (id, org_id, name, permissions, created_at)
		 VALUES (?, ?, ?, ?, ?)`,
		role.ID, role.OrgID, role.Name, string(perms), now,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return storage.ErrAlreadyExists
		}
		return fmt.Errorf("sqlite: create role: %w", err)
	}
	return nil
}

func (s *Store) GetRole(ctx context.Context, id string) (*storage.Role, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, org_id, name, permissions, created_at
		 FROM roles WHERE id = ?`, id)
	return scanRole(row)
}

func (s *Store) GetRoleByName(ctx context.Context, orgID, name string) (*storage.Role, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, org_id, name, permissions, created_at
		 FROM roles WHERE org_id = ? AND name = ?`, orgID, name)
	return scanRole(row)
}

func (s *Store) ListRoles(ctx context.Context, orgID string) ([]*storage.Role, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, org_id, name, permissions, created_at
		 FROM roles WHERE org_id = ? ORDER BY name ASC`, orgID)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list roles: %w", err)
	}
	defer rows.Close()

	var roles []*storage.Role
	for rows.Next() {
		r, err := scanRole(rows)
		if err != nil {
			return nil, err
		}
		roles = append(roles, r)
	}
	return roles, rows.Err()
}

func (s *Store) UpdateRole(ctx context.Context, role *storage.Role) error {
	perms, _ := json.Marshal(role.Permissions)
	res, err := s.db.ExecContext(ctx,
		`UPDATE roles SET name = ?, permissions = ? WHERE id = ?`,
		role.Name, string(perms), role.ID,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return storage.ErrAlreadyExists
		}
		return fmt.Errorf("sqlite: update role: %w", err)
	}
	return checkRowsAffected(res, "role")
}

func (s *Store) DeleteRole(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM roles WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("sqlite: delete role: %w", err)
	}
	return checkRowsAffected(res, "role")
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func scanOrg(row scanner) (*storage.Organization, error) {
	var o storage.Organization
	var domains, meta string
	var createdAt, updatedAt string
	err := row.Scan(&o.ID, &o.Slug, &o.Name, &domains, &meta, &createdAt, &updatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("sqlite: scan org: %w", err)
	}
	_ = json.Unmarshal([]byte(domains), &o.Domains)
	o.Metadata = json.RawMessage(meta)
	o.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	o.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
	return &o, nil
}

func scanMember(row scanner) (*storage.OrgMember, error) {
	var m storage.OrgMember
	var joinedAt string
	err := row.Scan(&m.OrgID, &m.UserID, &m.Role, &joinedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("sqlite: scan org member: %w", err)
	}
	m.JoinedAt, _ = time.Parse(time.RFC3339, joinedAt)
	return &m, nil
}

func scanRole(row scanner) (*storage.Role, error) {
	var r storage.Role
	var perms string
	var createdAt string
	err := row.Scan(&r.ID, &r.OrgID, &r.Name, &perms, &createdAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("sqlite: scan role: %w", err)
	}
	_ = json.Unmarshal([]byte(perms), &r.Permissions)
	r.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	return &r, nil
}

type scanner interface {
	Scan(dest ...any) error
}

func scanUser(row scanner) (*storage.User, error) {
	var u storage.User
	var disabled, emailVerified int
	var meta string
	var createdAt, updatedAt string
	err := row.Scan(&u.ID, &u.Email, &u.DisplayName, &disabled, &emailVerified, &meta, &createdAt, &updatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("sqlite: scan user: %w", err)
	}
	u.Disabled = disabled != 0
	u.EmailVerified = emailVerified != 0
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
	var createdAt, expiresAt, lastActiveAt, absoluteExpiresAt string
	err := row.Scan(&sess.ID, &sess.UserID, &sess.ClientID, &sess.IPAddress, &sess.UserAgent, &meta, &createdAt, &expiresAt, &lastActiveAt, &absoluteExpiresAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("sqlite: scan session: %w", err)
	}
	sess.Metadata = json.RawMessage(meta)
	sess.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	sess.ExpiresAt, _ = time.Parse(time.RFC3339, expiresAt)
	sess.LastActiveAt, _ = time.Parse(time.RFC3339, lastActiveAt)
	sess.AbsoluteExpiresAt, _ = time.Parse(time.RFC3339, absoluteExpiresAt)
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

// ---------------------------------------------------------------------------
// VerificationTokenStore
// ---------------------------------------------------------------------------

func (s *Store) CreateVerificationToken(ctx context.Context, token *storage.VerificationToken) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO verification_tokens (id, user_id, type, token_hash, expires_at, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		token.ID, token.UserID, token.Type, token.TokenHash,
		timeStr(token.ExpiresAt), timeStr(token.CreatedAt),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return storage.ErrAlreadyExists
		}
		return fmt.Errorf("sqlite: create verification token: %w", err)
	}
	return nil
}

func (s *Store) GetVerificationTokenByHash(ctx context.Context, hash string) (*storage.VerificationToken, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, user_id, type, token_hash, expires_at, created_at, used_at
		 FROM verification_tokens WHERE token_hash = ?`, hash)
	var t storage.VerificationToken
	var expiresAt, createdAt string
	var usedAt sql.NullString
	err := row.Scan(&t.ID, &t.UserID, &t.Type, &t.TokenHash, &expiresAt, &createdAt, &usedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("sqlite: get verification token: %w", err)
	}
	t.ExpiresAt, _ = time.Parse(time.RFC3339, expiresAt)
	t.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	if usedAt.Valid {
		parsed, _ := time.Parse(time.RFC3339, usedAt.String)
		t.UsedAt = &parsed
	}
	return &t, nil
}

func (s *Store) MarkTokenUsed(ctx context.Context, id string) error {
	now := timeStr(time.Now().UTC())
	res, err := s.db.ExecContext(ctx,
		`UPDATE verification_tokens SET used_at = ? WHERE id = ?`, now, id)
	if err != nil {
		return fmt.Errorf("sqlite: mark token used: %w", err)
	}
	return checkRowsAffected(res, "verification_token")
}

func (s *Store) DeleteExpiredTokens(ctx context.Context) (int64, error) {
	now := timeStr(time.Now().UTC())
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM verification_tokens WHERE expires_at < ? AND used_at IS NULL`, now)
	if err != nil {
		return 0, fmt.Errorf("sqlite: delete expired tokens: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
