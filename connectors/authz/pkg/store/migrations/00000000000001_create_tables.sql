-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS principals (
    id          VARCHAR(255) PRIMARY KEY,
    name        VARCHAR(255) NOT NULL,
    description VARCHAR(1024),
    type        VARCHAR(64)  NOT NULL,
    auth_config JSONB,
    active      BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMP NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_principals_type   ON principals(type);
CREATE INDEX IF NOT EXISTS idx_principals_active ON principals(active);

CREATE TABLE IF NOT EXISTS principal_policies (
    id           BIGSERIAL PRIMARY KEY,
    principal_id VARCHAR(255) NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    policy_id    VARCHAR(255) NOT NULL,
    granted_at   TIMESTAMP NOT NULL DEFAULT NOW(),
    granted_by   VARCHAR(255),
    UNIQUE (principal_id, policy_id)
);
CREATE INDEX IF NOT EXISTS idx_pp_principal ON principal_policies(principal_id);
CREATE INDEX IF NOT EXISTS idx_pp_policy    ON principal_policies(policy_id);

CREATE TABLE IF NOT EXISTS policies (
    id          VARCHAR(255) PRIMARY KEY,
    name        VARCHAR(255) NOT NULL,
    description VARCHAR(1024),
    rules       JSONB NOT NULL DEFAULT '[]',
    created_at  TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMP NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_policies_name ON policies(name);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS principal_policies;
DROP TABLE IF EXISTS policies;
DROP TABLE IF EXISTS principals;
-- +goose StatementEnd
