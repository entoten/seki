-- 004_credentials_webauthn.down.sql: Remove WebAuthn columns from credentials table (PostgreSQL)

DROP INDEX IF EXISTS idx_credentials_credential_id;

ALTER TABLE credentials DROP COLUMN IF EXISTS credential_id;
ALTER TABLE credentials DROP COLUMN IF EXISTS public_key;
ALTER TABLE credentials DROP COLUMN IF EXISTS attestation_type;
ALTER TABLE credentials DROP COLUMN IF EXISTS aaguid;
ALTER TABLE credentials DROP COLUMN IF EXISTS sign_count;
ALTER TABLE credentials DROP COLUMN IF EXISTS display_name;
ALTER TABLE credentials DROP COLUMN IF EXISTS last_used_at;
