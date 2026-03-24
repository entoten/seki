-- 011_client_auth_method.down.sql
ALTER TABLE clients DROP COLUMN jwks_uri;
ALTER TABLE clients DROP COLUMN token_endpoint_auth_method;
