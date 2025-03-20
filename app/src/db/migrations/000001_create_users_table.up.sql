CREATE TABLE "users" (
    "id" uuid NOT NULL PRIMARY KEY,
    "fullname" VARCHAR(255) NOT NULL,
    "username" VARCHAR(255) NOT NULL UNIQUE,
    "email" VARCHAR(255),
    "phone" VARCHAR(255),
    "hash_password" VARCHAR(2048) NOT NULL,
    "email_verified_at" TIMESTAMPTZ,
    "phone_verified_at" TIMESTAMPTZ,
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ,
    "deleted_at" TIMESTAMPTZ
);