-- 007_personal_access_tokens.up.sql: Personal access tokens (PostgreSQL)
-- Placeholder to keep postgres migrations in sync with sqlite.

CREATE TABLE IF NOT EXISTS personal_access_tokens (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    token_hash  TEXT NOT NULL UNIQUE,
    scopes      JSONB NOT NULL DEFAULT '[]',
    expires_at  TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
