-- +goose Up
-- +goose StatementBegin
ALTER TABLE policies ADD COLUMN IF NOT EXISTS http_rules JSONB;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE policies DROP COLUMN IF EXISTS http_rules;
-- +goose StatementEnd
