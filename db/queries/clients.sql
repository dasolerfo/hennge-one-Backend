-- name: CreateClient :one
INSERT INTO clients (
    client_source, client_name, client_secret, redirect_uris,
    client_type, token_endpoint_auth_method, grant_types, require_pkce
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
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
  client_source              = COALESCE(sqlc.narg(client_source), client_source),
  client_name                = COALESCE(sqlc.narg(client_name), client_name),
  client_secret              = COALESCE(sqlc.narg(client_secret), client_secret),
  redirect_uris              = COALESCE(sqlc.narg(redirect_uris)::text[], redirect_uris),
  client_type                = COALESCE(sqlc.narg(client_type), client_type),
  token_endpoint_auth_method = COALESCE(sqlc.narg(token_endpoint_auth_method), token_endpoint_auth_method),
  grant_types                = COALESCE(sqlc.narg(grant_types)::text[], grant_types),
  require_pkce               = COALESCE(sqlc.narg(require_pkce), require_pkce)
WHERE id = sqlc.arg(id)
RETURNING *;

-- name: DeleteClient :exec
DELETE FROM clients WHERE id = $1;
