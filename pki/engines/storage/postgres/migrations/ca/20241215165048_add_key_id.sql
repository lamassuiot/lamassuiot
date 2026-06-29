-- +goose Up
-- +goose StatementBegin

    -- Add key_id column to certificates table and populate it with serial_number
    ALTER TABLE ca_certificates ADD COLUMN key_id VARCHAR;
    UPDATE ca_certificates SET key_id = serial_number WHERE type = 'MANAGED';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE ca_certificates DROP COLUMN key_id;
-- +goose StatementEnd
