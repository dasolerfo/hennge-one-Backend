-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = $1;
-- name: GetUserByID :one
SELECT * FROM users WHERE id = $1;
-- name: GetUserBySub :one
SELECT * FROM users WHERE sub = $1;
-- name: CreateUser :one
INSERT INTO users (name, hashed_password, email, gender, email_verified)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;
-- name: GetAllUsers :many
SELECT * FROM users;
-- name: UpdateUser :one
UPDATE users SET
  name            = COALESCE(sqlc.narg(name), name),
  email           = COALESCE(sqlc.narg(email), email),
  hashed_password = COALESCE(sqlc.narg(hashed_password), hashed_password),
  gender          = COALESCE(sqlc.narg(gender), gender),
  email_verified  = COALESCE(sqlc.narg(email_verified), email_verified)
WHERE id = sqlc.arg(id)
RETURNING *;

-- name: DeleteUser :exec
DELETE FROM users WHERE id = $1;
