CREATE TABLE "user_mfas" (
    "id" uuid NOT NULL PRIMARY KEY,
    "user_id" uuid NOT NULL REFERENCES "users"("id"),
    "mfa_type" VARCHAR(255) NOT NULL,
    "metadata" JSONB NOT NULL,
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ,
    "deleted_at" TIMESTAMPTZ
);