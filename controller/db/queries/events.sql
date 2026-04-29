-- name: CreateEvent :one
INSERT INTO events (pot_id, time, service, kind, source, data)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: ListRecentEvents :many
SELECT * FROM events ORDER BY time DESC LIMIT $1;

-- name: ListEventsByPot :many
SELECT * FROM events WHERE pot_id = $1 ORDER BY time DESC LIMIT $2;
