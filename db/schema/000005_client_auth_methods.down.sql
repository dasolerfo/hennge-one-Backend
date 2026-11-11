ALTER TABLE "auth_codes" DROP COLUMN IF EXISTS "code_challenge_method";

ALTER TABLE "clients"
DROP CONSTRAINT IF EXISTS "clients_confidential_check",
DROP CONSTRAINT IF EXISTS "clients_public_check",
DROP CONSTRAINT IF EXISTS "clients_grant_types_check",
DROP CONSTRAINT IF EXISTS "clients_auth_method_check",
DROP CONSTRAINT IF EXISTS "clients_client_type_check";

ALTER TABLE "clients" ALTER COLUMN "client_secret" DROP DEFAULT;

ALTER TABLE "clients"
DROP COLUMN IF EXISTS "require_pkce",
DROP COLUMN IF EXISTS "grant_types",
DROP COLUMN IF EXISTS "token_endpoint_auth_method",
DROP COLUMN IF EXISTS "client_type";
