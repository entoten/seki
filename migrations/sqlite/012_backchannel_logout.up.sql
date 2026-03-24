-- 012_backchannel_logout.up.sql: Add backchannel logout fields to clients (SQLite)

ALTER TABLE clients ADD COLUMN backchannel_logout_uri TEXT NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN backchannel_logout_session_required INTEGER NOT NULL DEFAULT 0;
