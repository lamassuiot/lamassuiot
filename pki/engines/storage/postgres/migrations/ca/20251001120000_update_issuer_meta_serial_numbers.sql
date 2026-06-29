-- +goose Up
-- +goose StatementBegin

    -- Update certificates table: remove dashes from issuer_meta_serial_number
    UPDATE certificates
    SET issuer_meta_serial_number = REPLACE(issuer_meta_serial_number, '-', '')
    WHERE issuer_meta_serial_number IS NOT NULL 
      AND POSITION('-' IN issuer_meta_serial_number) > 0;

    -- Update ca_certificate_requests table: remove dashes from issuer_meta_serial_number
    UPDATE ca_certificate_requests
    SET issuer_meta_serial_number = REPLACE(issuer_meta_serial_number, '-', '')
    WHERE issuer_meta_serial_number IS NOT NULL 
      AND POSITION('-' IN issuer_meta_serial_number) > 0;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Note: Rollback is not implemented as it would require storing the original format
-- which is not feasible. This migration is irreversible.
SELECT 'This migration cannot be rolled back';
-- +goose StatementEnd