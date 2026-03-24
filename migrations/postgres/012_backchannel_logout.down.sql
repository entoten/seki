-- 012_backchannel_logout.down.sql
ALTER TABLE clients DROP COLUMN backchannel_logout_uri;
ALTER TABLE clients DROP COLUMN backchannel_logout_session_required;
