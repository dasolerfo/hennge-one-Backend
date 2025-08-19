CREATE TABLE "users" (
  "id" BIGINT PRIMARY KEY,
  "name" VARCHAR,
  "hashed_password" VARCHAR NOT NULL DEFAULT '12345678',
  "email" VARCHAR UNIQUE NOT NULL,
  "created_at" "TIMESTAMPTZ" NOT NULL DEFAULT (NOW())
);

CREATE TABLE auth_codes (
    "code" TEXT PRIMARY KEY,
    "client_id" TEXT NOT NULL,
    "redirect_uri" TEXT NOT NULL,
    "sub" TEXT NOT NULL,
    "scope" TEXT,
    "code_challenge" TEXT,
    "created_at" TIMESTAMP NOT NULL DEFAULT now(),
    "expires_at" TIMESTAMP NOT NULL
);