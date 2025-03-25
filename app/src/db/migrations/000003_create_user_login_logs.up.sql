CREATE TABLE "user_login_logs" (
    "id" UUID NOT NULL PRIMARY KEY,
    "request_id" UUID NOT NULL,
    "reference_id" UUID,
    "user_id" UUID,
    "username" VARCHAR(255) NOT NULL,
    "ip_address" VARCHAR(30),
    "user_agent" VARCHAR(255),
    "login_type" VARCHAR(255),
    "login_status" VARCHAR(255),
    "is_impersonation" BOOLEAN DEFAULT FALSE,
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ,
    "deleted_at" TIMESTAMPTZ
);