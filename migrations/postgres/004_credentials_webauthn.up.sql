-- 004_credentials_webauthn.up.sql: Add WebAuthn columns to credentials table (PostgreSQL)

ALTER TABLE credentials ADD COLUMN IF NOT EXISTS credential_id BYTEA;
ALTER TABLE credentials ADD COLUMN IF NOT EXISTS public_key BYTEA;
ALTER TABLE credentials ADD COLUMN IF NOT EXISTS attestation_type TEXT NOT NULL DEFAULT '';
ALTER TABLE credentials ADD COLUMN IF NOT EXISTS aaguid BYTEA;
ALTER TABLE credentials ADD COLUMN IF NOT EXISTS sign_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE credentials ADD COLUMN IF NOT EXISTS display_name TEXT NOT NULL DEFAULT '';
ALTER TABLE credentials ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_credentials_credential_id ON credentials (credential_id);
