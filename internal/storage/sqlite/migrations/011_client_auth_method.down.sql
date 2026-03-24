-- 011_client_auth_method.down.sql: Remove jwks_uri and token_endpoint_auth_method from clients (SQLite)
-- SQLite does not support DROP COLUMN before 3.35; this is best-effort.
ALTER TABLE clients DROP COLUMN jwks_uri;
ALTER TABLE clients DROP COLUMN token_endpoint_auth_method;
