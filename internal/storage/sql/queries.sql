-- name: GetSAMLRequest :one
SELECT id, relay_state, sp_acs_url, created_at, expires_at
FROM saml_requests
WHERE id = ?;

-- name: CreateSession :exec
INSERT INTO sessions (session_index, name_id, id_token, sp_entity_id, created_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?);

-- name: GetSession :one
SELECT session_index, name_id, id_token, sp_entity_id, created_at, expires_at
FROM sessions
WHERE session_index = ?;

-- name: DeleteSession :exec
DELETE FROM sessions WHERE session_index = ?;

-- name: DeleteExpiredSessions :exec
DELETE FROM sessions WHERE expires_at < ?;