CREATE TABLE device_codes (
    device_code TEXT PRIMARY KEY,
    user_code TEXT NOT NULL UNIQUE,
    client_id TEXT NOT NULL,
    scopes TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'pending',
    user_id TEXT,
    expires_at TEXT NOT NULL,
    interval INTEGER NOT NULL DEFAULT 5,
    created_at TEXT NOT NULL
);
