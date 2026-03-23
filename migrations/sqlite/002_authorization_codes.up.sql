-- 002_authorization_codes.up.sql: Add authorization_codes table (SQLite)

CREATE TABLE IF NOT EXISTS authorization_codes (
    code                  TEXT PRIMARY KEY,
    client_id             TEXT NOT NULL,
    user_id               TEXT NOT NULL,
    redirect_uri          TEXT NOT NULL,
    scopes                TEXT NOT NULL DEFAULT '[]',
    code_challenge        TEXT NOT NULL DEFAULT '',
    code_challenge_method TEXT NOT NULL DEFAULT '',
    nonce                 TEXT NOT NULL DEFAULT '',
    state                 TEXT NOT NULL DEFAULT '',
    expires_at            TEXT NOT NULL,
    created_at            TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
