-- +goose Up
-- +goose StatementBegin
-- central_key_generation marks a transaction whose response carried an
-- RFC 9483 Section 4.1.6 server-generated private key (CKG / KGA) wrapped in
-- CMS EnvelopedData alongside the issued certificate.
--
-- The generated private key is deliberately never persisted — it exists only
-- long enough to be wrapped into the response — so a CKG response cannot be
-- rebuilt after the fact. The flag lets handlePoll refuse a pollReq for such a
-- transaction instead of answering it with a bare certificate the end entity
-- holds no private key for. certConf and the confirmation-timeout monitor are
-- unaffected: both need only the stored certificate.
--
-- Existing rows default to false, which is correct: before this column existed
-- the CKG path never inserted a transaction row at all.
ALTER TABLE cmp_transactions
    ADD COLUMN IF NOT EXISTS central_key_generation BOOLEAN NOT NULL DEFAULT FALSE;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE cmp_transactions
    DROP COLUMN IF EXISTS central_key_generation;
-- +goose StatementEnd
