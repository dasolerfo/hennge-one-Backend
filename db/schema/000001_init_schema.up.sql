CREATE TABLE "users" (
  "id" BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  "name" VARCHAR NOT NULL,
  "hashed_password" VARCHAR NOT NULL DEFAULT '12345678',
  "email" VARCHAR UNIQUE NOT NULL,
  "email_verified" BOOLEAN NOT NULL DEFAULT FALSE,
  "gender" VARCHAR,
  "created_at" TIMESTAMPTZ NOT NULL DEFAULT (NOW())
);
CREATE TABLE auth_codes (
    "code" TEXT PRIMARY KEY,
    "client_id" TEXT NOT NULL,
    "redirect_uri" TEXT NOT NULL,
    "sub" TEXT NOT NULL,
    "scope" TEXT,
    "code_challenge" TEXT,
    "nonce" TEXT,
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
    "expires_at" TIMESTAMPTZ NOT NULL
);
CREATE TABLE clients (
    "id" TEXT NOT NULL PRIMARY KEY,
    "client_name" TEXT NOT NULL,
    "client_secret" TEXT NOT NULL,
    "redirect_uris" TEXT[] NOT NULL,
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT now()
);