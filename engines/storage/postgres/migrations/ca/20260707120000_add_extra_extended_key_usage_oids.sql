-- +goose Up
-- +goose StatementBegin
	ALTER TABLE issuance_profiles ADD COLUMN extra_extended_key_usage_o_ids text;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
	ALTER TABLE issuance_profiles DROP COLUMN extra_extended_key_usage_o_ids;
-- +goose StatementEnd
