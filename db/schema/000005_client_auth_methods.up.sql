ALTER TABLE "clients"
ADD COLUMN "client_type" TEXT NOT NULL DEFAULT 'confidential',
ADD COLUMN "token_endpoint_auth_method" TEXT NOT NULL DEFAULT 'client_secret_post',
ADD COLUMN "grant_types" TEXT[] NOT NULL DEFAULT '{authorization_code}',
ADD COLUMN "require_pkce" BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE "clients" ALTER COLUMN "client_secret" SET DEFAULT '';

ALTER TABLE "clients"
ADD CONSTRAINT "clients_client_type_check" CHECK ("client_type" IN ('public', 'confidential')),
ADD CONSTRAINT "clients_auth_method_check" CHECK ("token_endpoint_auth_method" IN ('none', 'client_secret_basic', 'client_secret_post')),
ADD CONSTRAINT "clients_grant_types_check" CHECK (cardinality("grant_types") > 0 AND "grant_types" <@ ARRAY['authorization_code', 'refresh_token', 'client_credentials']),
ADD CONSTRAINT "clients_public_check" CHECK ("client_type" <> 'public' OR ("token_endpoint_auth_method" = 'none' AND "client_secret" = '' AND "require_pkce")),
ADD CONSTRAINT "clients_confidential_check" CHECK ("client_type" <> 'confidential' OR ("token_endpoint_auth_method" <> 'none' AND "client_secret" <> ''));

ALTER TABLE "auth_codes" ADD COLUMN "code_challenge_method" TEXT;
