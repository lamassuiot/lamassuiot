-- +goose Up
-- +goose StatementBegin
SELECT 'up SQL query';
-- +goose StatementEnd

    ALTER TABLE certificates ADD COLUMN is_ca BOOLEAN;

    UPDATE certificates
    SET is_ca = EXISTS (
        SELECT 1
        FROM ca_certificates
        WHERE ca_certificates.serial_number = certificates.serial_number
    );

-- +goose Down
-- +goose StatementBegin
SELECT 'down SQL query';
-- +goose StatementEnd
