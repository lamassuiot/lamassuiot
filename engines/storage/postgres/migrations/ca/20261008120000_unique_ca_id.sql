-- +goose Up
-- Existing duplicate IDs must be resolved before applying this migration.
ALTER TABLE ca_certificates ADD CONSTRAINT ca_certificates_id_unique UNIQUE (id);

-- +goose Down
ALTER TABLE ca_certificates DROP CONSTRAINT ca_certificates_id_unique;
