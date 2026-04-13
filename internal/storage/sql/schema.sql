-- name: CreateSAMLRequestTable :exec
CREATE TABLE IF NOT EXISTS saml_requests (
    id TEXT PRIMARY KEY,
    relay_state TEXT NOT NULL,
    sp_acs_url TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

-- name: CreateSAMLRequestIndex :exec
CREATE INDEX IF NOT EXISTS idx_saml_requests_expires_at ON saml_requests(expires_at);

-- name: CreateSessionsTable :exec
CREATE TABLE IF NOT EXISTS sessions (
    session_index TEXT PRIMARY KEY,
    name_id TEXT NOT NULL,
    id_token TEXT NOT NULL,
    sp_entity_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

-- name: CreateSessionsIndexes :exec
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

-- name: CreateSessionsNameIDIndex :exec
CREATE INDEX IF NOT EXISTS idx_sessions_name_id ON sessions(name_id);