CREATE EXTENSION IF NOT EXISTS pgcrypto;

ALTER TABLE "users" ADD COLUMN "sub" UUID NOT NULL DEFAULT gen_random_uuid();
ALTER TABLE "users" ADD CONSTRAINT "users_sub_key" UNIQUE ("sub");
