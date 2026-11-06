-- +goose Up
-- +goose StatementBegin
ALTER TABLE issuance_profiles
	ADD COLUMN related_cert_enabled boolean NOT NULL DEFAULT false,
	ADD COLUMN related_cert_allowed_hosts text NOT NULL DEFAULT '[]',
	ADD COLUMN related_cert_max_age text NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE issuance_profiles
	DROP COLUMN related_cert_enabled,
	DROP COLUMN related_cert_allowed_hosts,
	DROP COLUMN related_cert_max_age;
-- +goose StatementEnd
