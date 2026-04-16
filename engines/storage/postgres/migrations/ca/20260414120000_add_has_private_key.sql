-- +goose Up
-- +goose StatementBegin
ALTER TABLE certificates
    ADD COLUMN has_private_key boolean DEFAULT false;

UPDATE certificates
SET has_private_key = CASE
    WHEN type IN ('MANAGED', 'IMPORTED_WITH_KEY') THEN true
    ELSE false
END;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE certificates
    DROP COLUMN has_private_key;
-- +goose StatementEnd
