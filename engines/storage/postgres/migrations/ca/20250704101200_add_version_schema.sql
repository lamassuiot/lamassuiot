-- +goose Up
-- +goose StatementBegin

    ALTER TABLE certificates ADD COLUMN version_schema VARCHAR;
	UPDATE certificates SET version_schema = 'unknown';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
	ALTER TABLE certificates DROP COLUMN version_schema;
-- +goose StatementEnd
