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
-- name: UpdateClient :one
UPDATE clients SET
  client_source = COALESCE(sqlc.narg(client_source), client_source),
  client_name   = COALESCE(sqlc.narg(client_name), client_name),
  client_secret = COALESCE(sqlc.narg(client_secret), client_secret),
  redirect_uris = COALESCE(sqlc.narg(redirect_uris)::text[], redirect_uris)
WHERE id = sqlc.arg(id)
RETURNING *;

-- name: DeleteClient :exec
DELETE FROM clients WHERE id = $1;
