-- 009_org_branding.down.sql: Remove branding column from organizations (SQLite)
-- SQLite does not support DROP COLUMN before 3.35.0; recreate the table.

CREATE TABLE organizations_backup AS
SELECT id, slug, name, domains, metadata, created_at, updated_at FROM organizations;

DROP TABLE organizations;

CREATE TABLE organizations (
    id         TEXT PRIMARY KEY,
    slug       TEXT UNIQUE NOT NULL,
    name       TEXT NOT NULL,
    domains    TEXT NOT NULL DEFAULT '[]',
    metadata   TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

INSERT INTO organizations SELECT * FROM organizations_backup;
DROP TABLE organizations_backup;

CREATE INDEX IF NOT EXISTS idx_organizations_slug ON organizations (slug);
