-- name: CreateAuthMethod :one
INSERT INTO auth_methods (user_id, method_type, method_data, is_active)
VALUES ($1, $2, $3, $4)
RETURNING id, user_id, method_type, method_data, is_active, created_at, updated_at;

-- name: GetAuthMethodByUserIDAndType :one
SELECT id, user_id, method_type, method_data, is_active, created_at, updated_at FROM auth_methods 
WHERE user_id = $1 AND method_type = $2 AND is_active = true
LIMIT 1;

-- name: GetAuthMethodsByUserID :many
SELECT id, user_id, method_type, method_data, is_active, created_at, updated_at FROM auth_methods 
WHERE user_id = $1 AND is_active = true
ORDER BY created_at DESC;

-- name: UpdateAuthMethod :one
UPDATE auth_methods
SET method_data = COALESCE($2, method_data),
    is_active = COALESCE($3, is_active),
    updated_at = NOW()
WHERE id = $1
RETURNING id, user_id, method_type, method_data, is_active, created_at, updated_at;

-- name: DeactivateAuthMethod :exec
UPDATE auth_methods
SET is_active = false, updated_at = NOW()
WHERE id = $1;
