-- 004_credentials_webauthn.down.sql: Remove WebAuthn columns from credentials table (SQLite)
-- SQLite does not support DROP COLUMN before 3.35.0, so we recreate the table.

DROP INDEX IF EXISTS idx_credentials_credential_id;

CREATE TABLE credentials_backup (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type        TEXT NOT NULL,
    secret      BLOB NOT NULL,
    metadata    TEXT NOT NULL DEFAULT '{}',
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

INSERT INTO credentials_backup (id, user_id, type, secret, metadata, created_at, updated_at)
SELECT id, user_id, type, COALESCE(secret, X''), COALESCE(metadata, '{}'), created_at, COALESCE(updated_at, created_at)
FROM credentials;

DROP TABLE credentials;
ALTER TABLE credentials_backup RENAME TO credentials;

CREATE INDEX IF NOT EXISTS idx_credentials_user_id ON credentials (user_id);
