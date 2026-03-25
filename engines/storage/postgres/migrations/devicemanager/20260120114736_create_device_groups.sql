-- +goose Up
-- +goose StatementBegin
CREATE TABLE device_groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    parent_id UUID REFERENCES device_groups(id) ON DELETE CASCADE,
    criteria JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_device_groups_parent ON device_groups(parent_id);
CREATE INDEX idx_device_groups_name ON device_groups(name);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_device_groups_name;
DROP INDEX IF EXISTS idx_device_groups_parent;
DROP TABLE IF EXISTS device_groups;
-- +goose StatementEnd
