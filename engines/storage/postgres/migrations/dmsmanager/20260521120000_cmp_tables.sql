-- +goose Up
-- +goose StatementBegin
-- CMP (RFC 4210 / RFC 9483) storage. This is the initial and only migration for
-- the CMP tables: the feature was developed across several incremental
-- migrations that were consolidated here before any of them shipped, so there
-- is no intermediate schema in the wild to upgrade from.

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
    transaction_id         TEXT        NOT NULL,
    -- DMS identifier this transaction belongs to (from the URL path param)
    dms_id                 TEXT        NOT NULL,
    -- state machine: PENDING | ISSUED | ISSUE_FAILED | CONFIRMED | REVOKED
    state                  TEXT        NOT NULL DEFAULT 'ISSUED',
    -- issued certificate stored as base64-encoded PEM; empty while PENDING
    certificate            TEXT        NOT NULL DEFAULT '',
    -- CSR stored as base64-encoded PEM; empty for ISSUED rows
    csr                    TEXT        NOT NULL DEFAULT '',
    -- senderNonce placed in the server response; hex-encoded, client echoes as recipNonce
    sent_nonce             TEXT        NOT NULL DEFAULT '',
    -- hex-encoded senderNonce from the EE's initiating ir/cr/kur request.
    -- RFC 9483 §3.1 requires each message to carry a fresh senderNonce; the
    -- certConf handler rejects (badSenderNonce) a confirmation that reuses it.
    received_nonce         TEXT        NOT NULL DEFAULT '',
    -- hex-encoded cert serial (denormalized) for fast revocation lookup
    cert_serial_number     TEXT        NOT NULL DEFAULT '',
    -- for key-update (kur) transactions, the hex serial of the certificate
    -- being updated (the request's protection cert). While the transaction is
    -- ISSUED-but-unconfirmed, RFC 9483 §4.1.3 forbids further operations with
    -- that certificate (second kur, new enrollments, revocation), so the
    -- enrollment/revocation paths key their pending-update check on this
    -- column. Empty for ir/cr transactions.
    superseded_cert_serial TEXT        NOT NULL DEFAULT '',
    -- absolute TTL deadline for in-flight rows
    expires_at             TIMESTAMPTZ NOT NULL,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    confirmed_at           TIMESTAMPTZ,
    -- human-readable error from the async worker on ISSUE_FAILED
    error_message          TEXT        NOT NULL DEFAULT '',
    -- true when the transaction was started by a KUR (key update / re-enroll)
    is_reenrollment        BOOL        NOT NULL DEFAULT FALSE,
    -- CMP body tag that started the transaction: "ir", "cr", or "kur"
    request_type           TEXT        NOT NULL DEFAULT '',
    -- CN from the CertTemplate (device ID); persisted to avoid re-parsing DER
    subject_common_name    TEXT        NOT NULL DEFAULT '',
    -- UUID of the WFX job mirroring this transaction; empty when WFX is off
    wfx_job_id             TEXT        NOT NULL DEFAULT '',
    -- RFC 4211 §6.1 id-regCtrl-regToken value carried by an ir/cr CertRequest's
    -- controls, when present; empty otherwise. See cmp_reg_token_claims below
    -- for the one-time-use enforcement this feeds.
    reg_token              TEXT        NOT NULL DEFAULT '',
    -- hex-encoded expected Rand.int value for an ir/cr transaction awaiting a
    -- challengeResp proof-of-possession round trip (RFC 4210bis §5.2.8.3): the
    -- row is inserted PENDING (with the synthesized CSR, as the phased-workflow
    -- approval flow already does) when popdecc is sent, and popdecr compares the
    -- EE's decrypted value against this column before resuming issuance. Empty
    -- for every other transaction.
    popo_challenge         TEXT        NOT NULL DEFAULT '',
    -- marks a transaction whose response carried an RFC 9483 §4.1.6
    -- server-generated private key (CKG / KGA) wrapped in CMS EnvelopedData
    -- alongside the issued certificate.
    --
    -- The generated private key is deliberately never persisted — it exists only
    -- long enough to be wrapped into the response — so a CKG response cannot be
    -- rebuilt after the fact. The flag lets handlePoll refuse a pollReq for such
    -- a transaction instead of answering it with a bare certificate the end
    -- entity holds no private key for. certConf and the confirmation-timeout
    -- monitor are unaffected: both need only the stored certificate.
    central_key_generation BOOLEAN     NOT NULL DEFAULT FALSE,
    -- security-audit metadata: how the requester's key possession and
    -- identity were established, captured at enrollment time so it survives
    -- later, unrelated changes to the DMS's configuration — see
    -- models.CMPTransaction's field docs for the full rationale.
    --
    -- which mechanism authenticated proof-of-possession of the enrolled key:
    -- "signature" | "trusted_ra" | "challenge_response" |
    -- "encrypted_certificate" | "csr_signature" | "kur_protection_cert" | ""
    -- (not applicable: rr, ccr, central key generation).
    popo_method                   TEXT NOT NULL DEFAULT '',
    -- only meaningful when popo_method = 'challenge_response': "legacy"
    -- (pvno cmp2000, deprecated `challenge` OCTET STRING, RFC 4210bis
    -- §5.2.8.3 v2) or "encrypted_rand" (pvno cmp2021, `encryptedRand` CMS
    -- EnvelopedData, RFC 9810 §5.1.3/§7). Empty otherwise.
    challenge_type                TEXT NOT NULL DEFAULT '',
    -- whether the request carried the CRMF id-regCtrl-authenticator control
    -- (RFC 4211 §6.2), independent of whether the DMS validates its value.
    authenticator_control_present BOOL NOT NULL DEFAULT FALSE,
    -- denormalized copy of the DMS's CMP auth_mode (models.CMPAuthMode) at
    -- the moment this transaction was created. The DMS's auth_mode is
    -- mutable, so this preserves the historical value even if the DMS is
    -- later reconfigured.
    auth_mode_at_enrollment       TEXT NOT NULL DEFAULT '',
    CONSTRAINT cmp_transactions_pkey PRIMARY KEY (transaction_id)
);

-- TTL cleanup: DELETE WHERE expires_at < now()
CREATE INDEX cmp_transactions_expires_at_idx
    ON cmp_transactions (expires_at);

-- Async worker poll: find PENDING rows oldest-first
CREATE INDEX cmp_transactions_state_created_idx
    ON cmp_transactions (state, created_at)
    WHERE state = 'PENDING';

-- MarkRevokedByCertSerial's narrow revocation lookup by cert serial.
CREATE INDEX cmp_transactions_cert_serial_idx
    ON cmp_transactions (cert_serial_number)
    WHERE cert_serial_number != '' AND state = 'CONFIRMED';

-- SelectByCertSerial looks up the transaction for a certificate serial
-- "regardless of state or expiry" (its own doc comment) — e.g. it must find a
-- REVOKED or PENDING row just as well as a CONFIRMED one, so it cannot use the
-- CONFIRMED-only index above.
CREATE INDEX cmp_transactions_cert_serial_any_state_idx
    ON cmp_transactions (cert_serial_number)
    WHERE cert_serial_number != '';

-- UI listing filtered by state
CREATE INDEX cmp_transactions_state_idx
    ON cmp_transactions (state);

-- HasUnconfirmedReenrollment and HasAbandonedReenrollment both filter on
-- (dms_id, superseded_cert_serial, is_reenrollment, state); they run on every
-- CMP enrollment, re-enrollment, and revocation request (dmsmanager_lwcmp.go),
-- so without an index the table is sequentially scanned on every one of those
-- calls as it grows. Both queries only ever match rows with
-- is_reenrollment = true and a non-empty superseded_cert_serial (both bail out
-- early otherwise), so that pair is expressed as the partial predicate rather
-- than indexed columns, keeping the index smaller.
CREATE INDEX cmp_transactions_dms_superseded_serial_idx
    ON cmp_transactions (dms_id, superseded_cert_serial, state)
    WHERE is_reenrollment AND superseded_cert_serial != '';

-- Lookup backing the one-time-use regToken check.
CREATE INDEX cmp_transactions_dms_reg_token_idx
    ON cmp_transactions (dms_id, reg_token)
    WHERE reg_token != '';

-- cmp_reg_token_claims records claimed RFC 4211 §6.1 id-regCtrl-regToken
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
CREATE TABLE cmp_reg_token_claims (
    dms_id     TEXT        NOT NULL,
    reg_token  TEXT        NOT NULL,
    claimed_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (dms_id, reg_token)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS cmp_reg_token_claims;
DROP TABLE IF EXISTS cmp_transactions;
-- +goose StatementEnd
