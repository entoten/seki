-- 009_org_branding.up.sql: Add branding column to organizations (PostgreSQL)

ALTER TABLE organizations ADD COLUMN IF NOT EXISTS branding JSONB NOT NULL DEFAULT '{}';
