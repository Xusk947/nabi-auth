-- name: GetAllTables :many
SELECT * FROM information_schema.tables WHERE table_schema = 'public';
