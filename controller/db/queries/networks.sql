-- name: ListNetworks :many
SELECT * FROM networks ORDER BY id;

-- name: GetNetwork :one
SELECT * FROM networks WHERE id = $1;

-- name: CreateNetwork :one
INSERT INTO networks (id, enabled, interface_id, type, vlan_id, subnet)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: UpdateNetwork :one
UPDATE networks
SET enabled = $2, interface_id = $3, type = $4, vlan_id = $5, subnet = $6
WHERE id = $1
RETURNING *;

-- name: DeleteNetwork :exec
DELETE FROM networks WHERE id = $1;
