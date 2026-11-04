-- +goose Up
-- +goose StatementBegin
-- Earlier versions recorded the certificates that use a key in its metadata and never removed them. The
-- certificates reference their key now (ca.certificates.key_id), so the stale list goes.
UPDATE kms_keys SET metadata = metadata - 'lamassu.io/kms/binded-resources'
WHERE metadata ? 'lamassu.io/kms/binded-resources';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- The list was derived data: there is nothing to restore.
SELECT 1;
-- +goose StatementEnd
