-- +goose Up
-- +goose StatementBegin
-- received_nonce stores the hex-encoded senderNonce from the EE's initiating
-- ir/cr/kur request. RFC 9483 Section 3.1 requires each message to carry a
-- fresh senderNonce; the certConf handler rejects (badSenderNonce) a
-- confirmation that reuses this value. Nullable-with-default so existing rows
-- and inserts that predate the column keep working.
ALTER TABLE cmp_transactions
    ADD COLUMN IF NOT EXISTS received_nonce TEXT NOT NULL DEFAULT '';

-- superseded_cert_serial stores, for key-update (kur) transactions, the hex
-- serial of the certificate being updated (the request's protection cert).
-- While the transaction is ISSUED-but-unconfirmed, RFC 9483 Section 4.1.3
-- forbids further operations with that certificate (second kur, new
-- enrollments, revocation), so the enrollment/revocation paths key their
-- pending-update check on this column. Empty for ir/cr transactions.
ALTER TABLE cmp_transactions
    ADD COLUMN IF NOT EXISTS superseded_cert_serial TEXT NOT NULL DEFAULT '';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE cmp_transactions
    DROP COLUMN IF EXISTS received_nonce;
ALTER TABLE cmp_transactions
    DROP COLUMN IF EXISTS superseded_cert_serial;
-- +goose StatementEnd
