CREATE TABLE "user_login_logs" (
    "id" UUID NOT NULL PRIMARY KEY,
    "request_id" UUID NOT NULL,
    "reference_id" UUID,
    "user_id" UUID,
    "ip_address" VARCHAR(30),
    "user_agent" VARCHAR(255),
    "device_id" VARCHAR(255),
    "metadata" JSONB,
    "login_type" VARCHAR(255) NOT NULL,
    "login_status" VARCHAR(255),
    "is_impersonation" BOOLEAN DEFAULT FALSE,
    "attempts" INTEGER DEFAULT 0,
    "required_mfa" BOOLEAN DEFAULT FALSE,
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ,
    "deleted_at" TIMESTAMPTZ
);