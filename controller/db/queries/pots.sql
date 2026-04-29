-- name: ListPots :many
SELECT * FROM pots ORDER BY created_at;

-- name: ListPotsByDeployment :many
SELECT * FROM pots WHERE deployment_id = $1 ORDER BY created_at;

-- name: GetPot :one
SELECT * FROM pots WHERE id = $1;

-- name: CreatePot :one
INSERT INTO pots (id, deployment_id, image_id, network_id, discriminator, status, ip, expires_at, cred_hint, mac)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
RETURNING *;

-- name: ListExpiredPots :many
SELECT * FROM pots WHERE expires_at IS NOT NULL AND expires_at <= NOW();

-- name: UpdatePotStatus :exec
UPDATE pots SET status = $2 WHERE id = $1;

-- name: UpdatePotIP :exec
UPDATE pots SET ip = $2 WHERE id = $1;

-- name: DeletePot :exec
DELETE FROM pots WHERE id = $1;

-- name: MaxDiscriminator :one
SELECT COALESCE(MAX(discriminator), 0)::integer AS max_disc
FROM pots
WHERE deployment_id = $1 AND network_id = $2 AND image_id = $3;
