-- +goose Up
-- +goose StatementBegin
-- Add state machine columns to cmp_transactions to support RFC 9483 §4.4
-- delayed delivery / polling (pollReq / pollRep).
--
-- A row's lifecycle:
--   PENDING (cert not yet issued)
--     │ async worker calls LWCEnroll/LWCReenroll
--     ▼
--   ISSUED  (cert_der populated)
--     │ certConf consumes the row OR TTL elapses
--     ▼
--   (deleted)
--
-- A row can also transition PENDING → ISSUE_FAILED when LWCEnroll returns
-- an error; error_message holds the reason so pollReq can surface it to the EE.
--
-- Existing rows are backfilled with state='ISSUED' to preserve the synchronous
-- behavior they were created under.
-- csr_der is NULL-able because ISSUED rows don't carry a CSR (the cert is in
-- cert_der instead). Same reason cert_der was relaxed below: it is NULL for
-- PENDING rows. GORM passes Go's nil []byte as SQL NULL, so the column types
-- must accept NULL to avoid a not-null violation on insert.
ALTER TABLE cmp_transactions
    ADD COLUMN state           TEXT  NOT NULL DEFAULT 'ISSUED',
    ADD COLUMN error_message   TEXT  NOT NULL DEFAULT '',
    ADD COLUMN csr_der         BYTEA,
    ADD COLUMN is_reenrollment BOOL  NOT NULL DEFAULT FALSE;

-- cert_der was NOT NULL; relax it so PENDING rows (no cert yet) can exist.
ALTER TABLE cmp_transactions
    ALTER COLUMN cert_der DROP NOT NULL;

-- Index for the worker's SelectPending: find PENDING rows oldest first.
CREATE INDEX cmp_transactions_state_created_idx
    ON cmp_transactions (state, created_at)
    WHERE state = 'PENDING';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS cmp_transactions_state_created_idx;
ALTER TABLE cmp_transactions
    DROP COLUMN IF EXISTS state,
    DROP COLUMN IF EXISTS error_message,
    DROP COLUMN IF EXISTS csr_der,
    DROP COLUMN IF EXISTS is_reenrollment;
ALTER TABLE cmp_transactions
    ALTER COLUMN cert_der SET NOT NULL;
-- +goose StatementEnd
