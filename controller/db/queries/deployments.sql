-- name: ListDeployments :many
SELECT * FROM deployments ORDER BY id;

-- name: GetDeployment :one
SELECT * FROM deployments WHERE id = $1;

-- name: CreateDeployment :one
INSERT INTO deployments (id, active, count, image_ids, network_ids, ipam, ttl_minutes)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: UpdateDeployment :one
UPDATE deployments
SET active = $2, count = $3, image_ids = $4, network_ids = $5, ipam = $6, ttl_minutes = $7
WHERE id = $1
RETURNING *;

-- name: DeleteDeployment :exec
DELETE FROM deployments WHERE id = $1;
