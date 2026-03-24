-- 006_verification_tokens.up.sql: Add verification tokens and email_verified column (PostgreSQL)

ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS verification_tokens (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type        TEXT NOT NULL,  -- 'email_verification', 'password_reset'
    token_hash  TEXT NOT NULL UNIQUE,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    used_at     TIMESTAMPTZ  -- NULL until used
);

CREATE INDEX IF NOT EXISTS idx_verification_tokens_user ON verification_tokens (user_id, type);
