-- name: CreateUser :one
INSERT INTO users (email, phone_number, telegram_username, telegram_id, avatar_url)
VALUES ($1, $2, $3, $4, $5)
RETURNING id, email, phone_number, telegram_username, telegram_id, avatar_url, created_at, updated_at;

-- name: GetUserByID :one
SELECT id, email, phone_number, telegram_username, telegram_id, avatar_url, created_at, updated_at FROM users WHERE id = $1 LIMIT 1;

-- name: GetUserByEmail :one
SELECT id, email, phone_number, telegram_username, telegram_id, avatar_url, created_at, updated_at FROM users WHERE email = $1 LIMIT 1;

-- name: GetUserByPhone :one
SELECT id, email, phone_number, telegram_username, telegram_id, avatar_url, created_at, updated_at FROM users WHERE phone_number = $1 LIMIT 1;

-- name: GetUserByTelegramID :one
SELECT id, email, phone_number, telegram_username, telegram_id, avatar_url, created_at, updated_at FROM users WHERE telegram_id = $1 LIMIT 1;

-- name: GetUserByTelegramUsername :one
SELECT id, email, phone_number, telegram_username, telegram_id, avatar_url, created_at, updated_at FROM users WHERE telegram_username = $1 LIMIT 1;

-- name: UpdateUser :one
UPDATE users
SET email = COALESCE($2, email),
    phone_number = COALESCE($3, phone_number),
    telegram_username = COALESCE($4, telegram_username),
    telegram_id = COALESCE($5, telegram_id),
    avatar_url = COALESCE($6, avatar_url),
    updated_at = NOW()
WHERE id = $1
RETURNING id, email, phone_number, telegram_username, telegram_id, avatar_url, created_at, updated_at;
