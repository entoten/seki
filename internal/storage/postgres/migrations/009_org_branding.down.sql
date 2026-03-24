-- 009_org_branding.down.sql: Remove branding column from organizations (PostgreSQL)

ALTER TABLE organizations DROP COLUMN IF EXISTS branding;
