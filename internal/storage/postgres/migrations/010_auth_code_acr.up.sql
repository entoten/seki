-- 010_auth_code_acr.up.sql: Add acr column to authorization_codes (Postgres)

ALTER TABLE authorization_codes ADD COLUMN acr TEXT NOT NULL DEFAULT '';
