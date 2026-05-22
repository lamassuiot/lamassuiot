-- +goose Up
-- +goose StatementBegin
-- Capture richer CMP transaction metadata so the management UI can show:
--   * request_type — the CMP body tag that started the transaction
--     ("ir", "cr", or "kur"). is_reenrollment is derivable from it
--     ("kur" → true), but we keep both so old rows (where request_type is
--     unknown) still surface their reenroll/initial distinction.
--   * subject_common_name — the CN from the CertTemplate, i.e. the device ID
--     associated with the enrollment. Persisted at insert time to avoid
--     reparsing CertDER on every listing.
ALTER TABLE cmp_transactions
    ADD COLUMN request_type        TEXT NOT NULL DEFAULT '',
    ADD COLUMN subject_common_name TEXT NOT NULL DEFAULT '';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE cmp_transactions
    DROP COLUMN IF EXISTS request_type,
    DROP COLUMN IF EXISTS subject_common_name;
-- +goose StatementEnd
