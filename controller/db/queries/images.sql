-- name: ListImages :many
SELECT * FROM images ORDER BY id;

-- name: GetImage :one
SELECT * FROM images WHERE id = $1;

-- name: UpsertImage :one
INSERT INTO images (id, base, version, os, features)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (id) DO UPDATE SET
    base     = EXCLUDED.base,
    version  = EXCLUDED.version,
    os       = EXCLUDED.os,
    features = EXCLUDED.features
RETURNING *;
