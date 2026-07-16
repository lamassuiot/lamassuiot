-- +goose Up
-- +goose StatementBegin
-- popo_challenge stores the hex-encoded expected Rand.int value for an ir/cr
-- transaction awaiting a challengeResp proof-of-possession round trip
-- (RFC 4210bis Section 5.2.8.3): the row is inserted PENDING (with the
-- synthesized CSR, as the phased-workflow approval flow already does) when
-- popdecc is sent, and popdecr compares the EE's decrypted value against this
-- column before resuming issuance. Empty for every other transaction.
ALTER TABLE cmp_transactions
    ADD COLUMN IF NOT EXISTS popo_challenge TEXT NOT NULL DEFAULT '';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE cmp_transactions
    DROP COLUMN IF EXISTS popo_challenge;
-- +goose StatementEnd
