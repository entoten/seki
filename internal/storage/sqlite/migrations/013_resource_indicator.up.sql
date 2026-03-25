-- 013_resource_indicator.up.sql: Add resource column to authorization_codes (RFC 8707)

ALTER TABLE authorization_codes ADD COLUMN resource TEXT NOT NULL DEFAULT '';
