-- 012_backchannel_logout.down.sql: Remove backchannel logout fields from clients (SQLite)
ALTER TABLE clients DROP COLUMN backchannel_logout_uri;
ALTER TABLE clients DROP COLUMN backchannel_logout_session_required;
