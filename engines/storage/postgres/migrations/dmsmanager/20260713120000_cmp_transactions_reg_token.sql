-- +goose Up
-- +goose StatementBegin
-- reg_token stores the RFC 4211 Section 6.1 id-regCtrl-regToken value carried
-- by an ir/cr CertRequest's controls, when present. It is empty for requests
-- that did not supply one. The token is intended for one-time use: once a
-- request carrying a given value has been accepted, HasSeenRegToken lets the
-- enrollment handler reject any later request presenting the same value.
ALTER TABLE cmp_transactions
    ADD COLUMN IF NOT EXISTS reg_token TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_cmp_transactions_dms_reg_token
    ON cmp_transactions (dms_id, reg_token)
    WHERE reg_token != '';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_cmp_transactions_dms_reg_token;
ALTER TABLE cmp_transactions
    DROP COLUMN IF EXISTS reg_token;
-- +goose StatementEnd
