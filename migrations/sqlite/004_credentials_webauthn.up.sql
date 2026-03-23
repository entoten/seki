-- 004_credentials_webauthn.up.sql: Add WebAuthn columns to credentials table (SQLite)

ALTER TABLE credentials ADD COLUMN credential_id BLOB;
ALTER TABLE credentials ADD COLUMN public_key BLOB;
ALTER TABLE credentials ADD COLUMN attestation_type TEXT NOT NULL DEFAULT '';
ALTER TABLE credentials ADD COLUMN aaguid BLOB;
ALTER TABLE credentials ADD COLUMN sign_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE credentials ADD COLUMN display_name TEXT NOT NULL DEFAULT '';
ALTER TABLE credentials ADD COLUMN last_used_at TEXT;

CREATE INDEX IF NOT EXISTS idx_credentials_credential_id ON credentials (credential_id);
