-- Schema for saml-oauth-proxy session storage
-- Stores SAML request state during OAuth flow

CREATE TABLE IF NOT EXISTS saml_requests (
    id TEXT PRIMARY KEY,
    relay_state TEXT NOT NULL,
    sp_acs_url TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

-- Index for cleanup of expired requests
CREATE INDEX IF NOT EXISTS idx_saml_requests_expires_at ON saml_requests(expires_at);

-- Queries for sqlc
-- name: CreateSAMLRequest :exec
INSERT INTO saml_requests (id, relay_state, sp_acs_url, created_at, expires_at)
VALUES (?, ?, ?, ?, ?);

-- name: GetSAMLRequest :one
SELECT id, relay_state, sp_acs_url, created_at, expires_at
FROM saml_requests
WHERE id = ?;

-- name: DeleteSAMLRequest :exec
DELETE FROM saml_requests WHERE id = ?;

-- name: DeleteExpiredRequests :exec
DELETE FROM saml_requests WHERE expires_at < ?;
