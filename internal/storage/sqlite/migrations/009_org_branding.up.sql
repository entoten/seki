-- 009_org_branding.up.sql: Add branding column to organizations (SQLite)

ALTER TABLE organizations ADD COLUMN branding TEXT NOT NULL DEFAULT '{}';
