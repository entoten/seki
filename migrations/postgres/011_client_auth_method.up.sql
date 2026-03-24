-- 011_client_auth_method.up.sql: Add jwks_uri and token_endpoint_auth_method to clients (Postgres)

ALTER TABLE clients ADD COLUMN jwks_uri TEXT NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN token_endpoint_auth_method TEXT NOT NULL DEFAULT '';
