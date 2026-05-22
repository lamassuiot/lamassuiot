-- +goose Up
-- +goose StatementBegin
-- cmp_transactions stores server-side state for every CMP enrollment
-- transaction (RFC 4210 §5.1.1 / RFC 9483).
--
-- Lifecycle:
--   PENDING (cert not yet issued, async mode)
--     │ async worker calls LWCEnroll/LWCReenroll
--     ▼
--   ISSUED  (cert issued, awaiting certConf)
--     │ certConf received
--     ▼
--   CONFIRMED → (optionally) REVOKED
--
--   PENDING → ISSUE_FAILED  (async worker error)
--
-- Terminal states (CONFIRMED, REVOKED, ISSUE_FAILED) are retained for audit.
-- Only in-flight states (PENDING, ISSUED) are subject to TTL expiry.
CREATE TABLE cmp_transactions (
    -- hex-encoded bytes of the PKIHeader transactionID field
    transaction_id      TEXT        NOT NULL,
    -- DMS identifier this transaction belongs to (from the URL path param)
    dms_id              TEXT        NOT NULL,
    -- state machine: PENDING | ISSUED | ISSUE_FAILED | CONFIRMED | REVOKED
    state               TEXT        NOT NULL DEFAULT 'ISSUED',
    -- issued certificate stored as base64-encoded PEM; empty while PENDING
    certificate         TEXT        NOT NULL DEFAULT '',
    -- CSR stored as base64-encoded PEM; empty for ISSUED rows
    csr                 TEXT        NOT NULL DEFAULT '',
    -- senderNonce placed in the server response; hex-encoded, client echoes as recipNonce
    sent_nonce          TEXT        NOT NULL DEFAULT '',
    -- hex-encoded cert serial (denormalized) for fast revocation lookup
    cert_serial_number  TEXT        NOT NULL DEFAULT '',
    -- absolute TTL deadline for in-flight rows
    expires_at          TIMESTAMPTZ NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    confirmed_at        TIMESTAMPTZ,
    -- human-readable error from the async worker on ISSUE_FAILED
    error_message       TEXT        NOT NULL DEFAULT '',
    -- true when the transaction was started by a KUR (key update / re-enroll)
    is_reenrollment     BOOL        NOT NULL DEFAULT FALSE,
    -- CMP body tag that started the transaction: "ir", "cr", or "kur"
    request_type        TEXT        NOT NULL DEFAULT '',
    -- CN from the CertTemplate (device ID); persisted to avoid re-parsing DER
    subject_common_name TEXT        NOT NULL DEFAULT '',
    -- UUID of the WFX job mirroring this transaction; empty when WFX is off
    wfx_job_id          TEXT        NOT NULL DEFAULT '',
    CONSTRAINT cmp_transactions_pkey PRIMARY KEY (transaction_id)
);

-- TTL cleanup: DELETE WHERE expires_at < now()
CREATE INDEX cmp_transactions_expires_at_idx
    ON cmp_transactions (expires_at);

-- Async worker poll: find PENDING rows oldest-first
CREATE INDEX cmp_transactions_state_created_idx
    ON cmp_transactions (state, created_at)
    WHERE state = 'PENDING';

-- Revocation lookup by cert serial
CREATE INDEX cmp_transactions_cert_serial_idx
    ON cmp_transactions (cert_serial_number)
    WHERE cert_serial_number != '' AND state = 'CONFIRMED';

-- UI listing filtered by state
CREATE INDEX cmp_transactions_state_idx
    ON cmp_transactions (state);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS cmp_transactions;
-- +goose StatementEnd
