-- +goose Up
-- +goose StatementBegin

    -- BEGIN;

    -- 1. Drop the foreign key constraint from ca_certificates
    ALTER TABLE ca_certificates DROP CONSTRAINT fk_serial_number;

    -- 2. Update certificates and ca_certificates tables: remove dashes

    UPDATE certificates
    SET serial_number = REPLACE(serial_number, '-', '')
    WHERE POSITION('-' IN serial_number) > 0;

    -- Update the child table
    UPDATE ca_certificates
    SET serial_number = REPLACE(serial_number, '-', '')
    WHERE POSITION('-' IN serial_number) > 0;

    -- 3. Restore foreign key constraint to certificates table for certificate_serial_number
    ALTER TABLE ca_certificates
        ADD CONSTRAINT fk_serial_number
        FOREIGN KEY (serial_number) REFERENCES certificates (serial_number)
        ON DELETE CASCADE;
    
    -- COMMIT;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SELECT 'down SQL query';
-- +goose StatementEnd
