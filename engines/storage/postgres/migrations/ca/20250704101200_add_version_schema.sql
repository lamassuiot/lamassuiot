-- +goose Up
-- +goose StatementBegin

    ALTER TABLE certificates ADD COLUMN version_schema VARCHAR;
	UPDATE certificates SET version_schema = 'unknown';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
	DROP COLUMN version_schema FROM certificates;
-- +goose StatementEnd
