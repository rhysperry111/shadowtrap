-- name: GetHost :one
SELECT * FROM network_host WHERE id = 1;

-- name: UpsertHost :exec
INSERT INTO network_host (id, network, mode, static_ip, static_gateway, static_dns)
VALUES (1, $1, $2, $3, $4, $5)
ON CONFLICT (id) DO UPDATE SET
    network        = EXCLUDED.network,
    mode           = EXCLUDED.mode,
    static_ip      = EXCLUDED.static_ip,
    static_gateway = EXCLUDED.static_gateway,
    static_dns     = EXCLUDED.static_dns;
