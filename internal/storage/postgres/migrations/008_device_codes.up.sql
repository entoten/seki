-- 008_device_codes.up.sql: Device authorization codes (PostgreSQL)
-- Placeholder to keep postgres migrations in sync with sqlite.

CREATE TABLE IF NOT EXISTS device_codes (
    device_code  TEXT PRIMARY KEY,
    user_code    TEXT NOT NULL UNIQUE,
    client_id    TEXT NOT NULL,
    scopes       JSONB NOT NULL DEFAULT '[]',
    status       TEXT NOT NULL DEFAULT 'pending',
    user_id      TEXT,
    expires_at   TIMESTAMPTZ NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
