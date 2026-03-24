-- 010_auth_code_acr.down.sql: Remove acr column from authorization_codes (Postgres)

ALTER TABLE authorization_codes DROP COLUMN acr;
