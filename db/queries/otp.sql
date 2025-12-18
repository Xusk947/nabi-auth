-- name: CreateOTPCode :one
INSERT INTO otp_codes (user_id, identifier, code_hash, expires_at)
VALUES ($1, $2, $3, $4)
RETURNING id, user_id, identifier, code_hash, expires_at, used, attempts, created_at;

-- name: GetOTPCodeByIdentifier :one
SELECT id, user_id, identifier, code_hash, expires_at, used, attempts, created_at FROM otp_codes 
WHERE identifier = $1 AND used = false AND expires_at > NOW()
ORDER BY created_at DESC
LIMIT 1;

-- name: MarkOTPAsUsed :exec
UPDATE otp_codes
SET used = true
WHERE id = $1;

-- name: IncrementOTPAttempts :exec
UPDATE otp_codes
SET attempts = attempts + 1
WHERE id = $1;

-- name: DeleteExpiredOTPCodes :exec
DELETE FROM otp_codes WHERE expires_at < NOW();
