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