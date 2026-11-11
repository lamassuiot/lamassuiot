-- +goose Up
ALTER TABLE policies ADD http_rules JSON;

-- +goose Down
ALTER TABLE policies DROP COLUMN http_rules;
