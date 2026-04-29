-- name: ListInterfaces :many
SELECT * FROM interfaces ORDER BY id;

-- name: GetInterface :one
SELECT * FROM interfaces WHERE id = $1;

-- name: UpsertInterface :exec
INSERT INTO interfaces (id, enabled, link, mode, aggregate_group)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (id) DO UPDATE SET
    enabled         = EXCLUDED.enabled,
    link            = EXCLUDED.link,
    mode            = EXCLUDED.mode,
    aggregate_group = EXCLUDED.aggregate_group;
