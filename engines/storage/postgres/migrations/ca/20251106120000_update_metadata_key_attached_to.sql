-- +goose Up
-- +goose StatementBegin
-- Update metadata key from 'lamassu.io/ca/attached-to' to 'lamassu.io/ra/attached-to'
-- in both ca_certificates and certificates tables

-- Update ca_certificates table
UPDATE ca_certificates
SET metadata = jsonb_set(
    (metadata::jsonb - 'lamassu.io/ca/attached-to'),
    '{lamassu.io/ra/attached-to}',
    (metadata::jsonb -> 'lamassu.io/ca/attached-to'),
    true
)::text
WHERE metadata::jsonb ? 'lamassu.io/ca/attached-to';

-- Update certificates table
UPDATE certificates
SET metadata = jsonb_set(
    (metadata::jsonb - 'lamassu.io/ca/attached-to'),
    '{lamassu.io/ra/attached-to}',
    (metadata::jsonb -> 'lamassu.io/ca/attached-to'),
    true
)::text
WHERE metadata::jsonb ? 'lamassu.io/ca/attached-to';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Rollback: Revert metadata key from 'lamassu.io/ra/attached-to' back to 'lamassu.io/ca/attached-to'
-- in both ca_certificates and certificates tables

-- Rollback ca_certificates table
UPDATE ca_certificates
SET metadata = jsonb_set(
    (metadata::jsonb - 'lamassu.io/ra/attached-to'),
    '{lamassu.io/ca/attached-to}',
    (metadata::jsonb -> 'lamassu.io/ra/attached-to'),
    true
)::text
WHERE metadata::jsonb ? 'lamassu.io/ra/attached-to';

-- Rollback certificates table
UPDATE certificates
SET metadata = jsonb_set(
    (metadata::jsonb - 'lamassu.io/ra/attached-to'),
    '{lamassu.io/ca/attached-to}',
    (metadata::jsonb -> 'lamassu.io/ra/attached-to'),
    true
)::text
WHERE metadata::jsonb ? 'lamassu.io/ra/attached-to';
-- +goose StatementEnd
