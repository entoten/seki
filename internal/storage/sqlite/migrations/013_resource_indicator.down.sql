-- 013_resource_indicator.down.sql: Remove resource column from authorization_codes

ALTER TABLE authorization_codes DROP COLUMN resource;
