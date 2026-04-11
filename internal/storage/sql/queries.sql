-- name: GetSAMLRequest :one
SELECT id, relay_state, sp_acs_url, created_at, expires_at
FROM saml_requests
WHERE id = ?;