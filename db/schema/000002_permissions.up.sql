CREATE TABLE permissions (
    "id" SERIAL PRIMARY KEY,
    "user_id" BIGINT NOT NULL,
    "client_id" TEXT NOT NULL,
    "allowed" BOOLEAN NOT NULL DEFAULT FALSE,
    "granted_at" TIMESTAMP DEFAULT NOW()    
);
alter table "permissions" add FOREIGN KEY ("client_id") references "clients" ("id") on delete cascade;
alter table "permissions" add FOREIGN KEY ("user_id") references "users" ("id") on delete cascade;

    