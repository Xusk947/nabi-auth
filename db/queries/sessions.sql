-- name: CreateSession :one
INSERT INTO sessions (user_id, token, refresh_token, expires_at)
VALUES ($1, $2, $3, $4)
RETURNING id, user_id, token, refresh_token, expires_at, created_at;

-- name: GetSessionByToken :one
SELECT id, user_id, token, refresh_token, expires_at, created_at FROM sessions WHERE token = $1 LIMIT 1;

-- name: GetSessionByRefreshToken :one
SELECT id, user_id, token, refresh_token, expires_at, created_at FROM sessions WHERE refresh_token = $1 LIMIT 1;

-- name: DeleteSession :exec
DELETE FROM sessions WHERE id = $1;

-- name: DeleteSessionByToken :exec
DELETE FROM sessions WHERE token = $1;

-- name: DeleteSessionByRefreshToken :exec
DELETE FROM sessions WHERE refresh_token = $1;

-- name: DeleteUserSessions :exec
DELETE FROM sessions WHERE user_id = $1;

-- name: DeleteExpiredSessions :exec
DELETE FROM sessions WHERE expires_at < NOW();
