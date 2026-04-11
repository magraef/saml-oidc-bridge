-- name: CreateSAMLRequest :exec
INSERT INTO saml_requests (id, relay_state, sp_acs_url, created_at, expires_at)
VALUES (?, ?, ?, ?, ?);

-- name: DeleteSAMLRequest :exec
DELETE FROM saml_requests WHERE id = ?;

-- name: DeleteExpiredRequests :exec
DELETE FROM saml_requests WHERE expires_at < ?;
