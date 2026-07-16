-- +goose Up
-- +goose StatementBegin
-- HasUnconfirmedReenrollment and HasAbandonedReenrollment both filter on
-- (dms_id, superseded_cert_serial, is_reenrollment, state); they run on every
-- CMP enrollment, re-enrollment, and revocation request (dmsmanager_lwcmp.go),
-- so without an index the table is sequentially scanned on every one of those
-- calls as it grows. Both queries only ever match rows with
-- is_reenrollment = true and a non-empty superseded_cert_serial (both bail out
-- early otherwise), so that pair is expressed as the partial predicate rather
-- than indexed columns, keeping the index smaller.
CREATE INDEX IF NOT EXISTS idx_cmp_transactions_dms_superseded_serial
    ON cmp_transactions (dms_id, superseded_cert_serial, state)
    WHERE is_reenrollment AND superseded_cert_serial != '';

-- SelectByCertSerial looks up the transaction for a certificate serial
-- "regardless of state or expiry" (its own doc comment) — e.g. it must find a
-- REVOKED or PENDING row just as well as a CONFIRMED one. The existing
-- cmp_transactions_cert_serial_idx (added in
-- 20260521120000_cmp_transactions_request_metadata.sql) is scoped to
-- state = 'CONFIRMED' for MarkRevokedByCertSerial's narrower query, so
-- SelectByCertSerial's any-state lookup can't use it and falls back to a
-- sequential scan. This index covers that lookup without touching the
-- existing CONFIRMED-only one.
CREATE INDEX IF NOT EXISTS idx_cmp_transactions_cert_serial_any_state
    ON cmp_transactions (cert_serial_number)
    WHERE cert_serial_number != '';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_cmp_transactions_dms_superseded_serial;
DROP INDEX IF EXISTS idx_cmp_transactions_cert_serial_any_state;
-- +goose StatementEnd
