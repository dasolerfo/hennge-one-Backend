-- name: CreateAuthCode :one
INSERT INTO auth_codes (
    code, client_id, redirect_uri, sub, scope, code_challenge, nonce, expires_at
) VALUES ( $1, $2, $3, $4, $5, $6, $7, $8 ) RETURNING *;
-- name: GetAuthCode :one
SELECT * FROM auth_codes 
WHERE code = $1 AND expires_at > now();