-- name: GetAPIKey :one
SELECT * FROM api_keys WHERE key_hash = $1;

-- name: GetAPIKeyByName :one
SELECT * FROM api_keys WHERE name = $1;

-- name: ListAPIKeys :many
SELECT * FROM api_keys ORDER BY created_at;

-- name: CreateAPIKey :one
INSERT INTO api_keys (key_hash, name, role)
VALUES ($1, $2, $3)
RETURNING *;

-- name: DeleteAPIKeyByName :exec
DELETE FROM api_keys WHERE name = $1;
