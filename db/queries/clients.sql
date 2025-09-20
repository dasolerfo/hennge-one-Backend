-- name: CreateClient :one
INSERT INTO clients (client_source, client_name, client_secret, redirect_uris)
VALUES ($1, $2, $3, $4)
RETURNING *;
-- name: GetClientByID :one
SELECT * FROM clients
WHERE id = $1;
-- name: GetClientBysource :one
SELECT * FROM clients
WHERE client_source = $1;
-- name: ListClients :many
SELECT * FROM clients
ORDER BY id;