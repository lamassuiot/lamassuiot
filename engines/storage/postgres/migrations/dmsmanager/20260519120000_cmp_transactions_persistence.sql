-- +goose Up
-- +goose StatementBegin
-- Add persistence columns so CMP transactions survive certConf and revocation.
--
-- Updated lifecycle:
--   PENDING → ISSUED → CONFIRMED → (optionally) REVOKED
--                    → ISSUE_FAILED
--
-- Terminal states (CONFIRMED, REVOKED) are retained indefinitely for audit.
-- Only in-flight states (PENDING, ISSUED, ISSUE_FAILED) are subject to TTL
-- expiration via DeleteExpired.

-- cert_serial_number: hex-encoded cert serial (denormalized from cert_der) for
-- efficient lookup when a revocation arrives by serial number.
ALTER TABLE cmp_transactions
    ADD COLUMN cert_serial_number TEXT NOT NULL DEFAULT '',
    ADD COLUMN confirmed_at       TIMESTAMPTZ;

-- Index for MarkRevokedByCertSerial: find CONFIRMED rows by cert serial.
CREATE INDEX cmp_transactions_cert_serial_idx
    ON cmp_transactions (cert_serial_number)
    WHERE cert_serial_number != '' AND state = 'CONFIRMED';

-- Index for the UI listing filtered by state (active vs completed).
CREATE INDEX cmp_transactions_state_idx
    ON cmp_transactions (state);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS cmp_transactions_state_idx;
DROP INDEX IF EXISTS cmp_transactions_cert_serial_idx;
ALTER TABLE cmp_transactions
    DROP COLUMN IF EXISTS cert_serial_number,
    DROP COLUMN IF EXISTS confirmed_at;
-- +goose StatementEnd
