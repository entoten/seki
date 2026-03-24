-- 010_auth_code_acr.down.sql: Remove acr column from authorization_codes (SQLite)
-- SQLite does not support DROP COLUMN before 3.35.0, so we recreate the table.

CREATE TABLE authorization_codes_backup AS SELECT code, client_id, user_id, redirect_uri, scopes, code_challenge, code_challenge_method, nonce, state, expires_at, created_at FROM authorization_codes;
DROP TABLE authorization_codes;
ALTER TABLE authorization_codes_backup RENAME TO authorization_codes;
