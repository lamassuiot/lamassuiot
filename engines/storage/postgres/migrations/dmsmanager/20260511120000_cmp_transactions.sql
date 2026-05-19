-- +goose Up
-- +goose StatementBegin
-- cmp_transactions stores server-side state for in-flight CMP enrollment
-- transactions (RFC 4210 §5.1.1 / RFC 9483).  A row exists from the moment
-- the server sends an IP/CP/KUP response until:
--   (a) the client sends a matching certConf and the server removes it, or
--   (b) expires_at elapses and the periodic cleanup job removes it.
--
-- PRIMARY KEY on transaction_id enforces uniqueness, enabling atomic replay-
-- attack detection: a duplicate INSERT fails rather than silently overwriting.
CREATE TABLE cmp_transactions (
    -- hex-encoded bytes of the PKIHeader transactionID field
    transaction_id  TEXT        NOT NULL,
    -- DMS identifier this transaction belongs to (from the URL path param)
    dms_id          TEXT        NOT NULL,
    -- raw DER of the issued certificate; used to verify certHash in certConf
    cert_der        BYTEA       NOT NULL,
    -- senderNonce placed in the server's response; client echoes it as recipNonce
    sent_nonce      BYTEA       NOT NULL,
    -- absolute TTL deadline: rows past this timestamp are stale and deletable
    expires_at      TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT cmp_transactions_pkey PRIMARY KEY (transaction_id)
);
-- Index for efficient TTL cleanup: DELETE WHERE expires_at < now()
CREATE INDEX cmp_transactions_expires_at_idx ON cmp_transactions (expires_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS cmp_transactions;
-- +goose StatementEnd
