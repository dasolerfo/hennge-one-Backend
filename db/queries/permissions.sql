-- name: CreatePermission :one
INSERT INTO permissions (user_id, client_id, allowed)
VALUES ($1, $2, $3)
RETURNING id, user_id, client_id, allowed, granted_at;
-- name: GetPermissionByUserAndClient :one
SELECT * FROM permissions
WHERE user_id = $1 AND client_id = $2;
-- name: UpdatePermission :one
UPDATE permissions set allowed = $3, granted_at = NOW()
WHERE user_id = $1 AND client_id = $2
RETURNING id, user_id, client_id, allowed, granted_at;