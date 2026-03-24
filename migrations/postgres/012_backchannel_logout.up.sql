-- 012_backchannel_logout.up.sql: Add backchannel logout fields to clients (Postgres)

ALTER TABLE clients ADD COLUMN backchannel_logout_uri TEXT NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN backchannel_logout_session_required BOOLEAN NOT NULL DEFAULT FALSE;
