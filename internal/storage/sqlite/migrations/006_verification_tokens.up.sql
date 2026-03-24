-- 006_verification_tokens.up.sql: Add verification tokens and email_verified column (SQLite)

ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS verification_tokens (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type        TEXT NOT NULL,  -- 'email_verification', 'password_reset'
    token_hash  TEXT NOT NULL UNIQUE,
    expires_at  TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    used_at     TEXT  -- NULL until used
);

CREATE INDEX IF NOT EXISTS idx_verification_tokens_user ON verification_tokens (user_id, type);
