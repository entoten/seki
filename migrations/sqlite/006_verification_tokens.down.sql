-- 006_verification_tokens.down.sql

DROP INDEX IF EXISTS idx_verification_tokens_user;
DROP TABLE IF EXISTS verification_tokens;
ALTER TABLE users DROP COLUMN email_verified;
