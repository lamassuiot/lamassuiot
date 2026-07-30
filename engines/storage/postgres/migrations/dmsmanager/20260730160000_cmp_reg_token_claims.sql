-- +goose Up
-- +goose StatementBegin
-- cmp_reg_token_claims records claimed RFC 4211 Section 6.1 id-regCtrl-regToken
-- values, enforcing their one-time use.
--
-- This is deliberately a separate table from cmp_transactions rather than a
-- unique index on cmp_transactions.reg_token. A transaction row can only be
-- written AFTER issuance, because it carries the issued certificate; but the
-- one-time-use decision has to be made BEFORE issuance, or two concurrent
-- requests presenting the same token both read "unseen" and both enrol. A unique
-- index on the transaction row would not fix that either: it would let both
-- requests issue and then fail the second insert, orphaning a certificate that
-- exists at the CA but was reported to the client as a failure.
--
-- The composite primary key is what makes the claim atomic: INSERT ... ON
-- CONFLICT DO NOTHING lets exactly one concurrent caller report RowsAffected=1.
CREATE TABLE IF NOT EXISTS cmp_reg_token_claims (
    dms_id     TEXT        NOT NULL,
    reg_token  TEXT        NOT NULL,
    claimed_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (dms_id, reg_token)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS cmp_reg_token_claims;
-- +goose StatementEnd
