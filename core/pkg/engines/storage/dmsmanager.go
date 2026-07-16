package storage

import (
	"context"
	"time"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
)

// CMPTransactionState is the lifecycle state of a CMP transaction.
// In synchronous issuance mode (the default), transactions are created already
// in the ISSUED state. In asynchronous-issuance mode (RFC 9483 §4.4 delayed
// delivery), the controller creates the row in PENDING state and a background
// worker transitions it to ISSUED (with the cert bytes) or ISSUE_FAILED
// (with an ErrorMessage).
type CMPTransactionState string

const (
	// CMPTransactionStatePending means the enrollment request has been accepted
	// but the cert has not yet been issued. A background worker is responsible
	// for transitioning the row to ISSUED or ISSUE_FAILED.
	CMPTransactionStatePending CMPTransactionState = "PENDING"
	// CMPTransactionStateIssued means the cert has been issued and is held in
	// the row's CertDER, awaiting either certConf (explicit confirmation)
	// or expiry. Both pollReq and certConf operate on rows in this state.
	CMPTransactionStateIssued CMPTransactionState = "ISSUED"
	// CMPTransactionStateIssueFailed means the async worker tried to issue the
	// cert but the CA rejected the request. The reason is stored in
	// ErrorMessage so pollReq can surface a meaningful CMP error to the EE.
	CMPTransactionStateIssueFailed CMPTransactionState = "ISSUE_FAILED"
	// CMPTransactionStateConfirmed means the EE sent a valid certConf and the
	// server responded with pkiConf. The enrollment is complete. Rows in this
	// state are retained for audit/UI visibility and are NOT swept by
	// DeleteExpired.
	CMPTransactionStateConfirmed CMPTransactionState = "CONFIRMED"
	// CMPTransactionStateRevoked means the certificate that was enrolled in
	// this transaction has been subsequently revoked (via CMP rr or other
	// channel). The row persists for audit visibility.
	CMPTransactionStateRevoked CMPTransactionState = "REVOKED"
)

// CMPTransaction holds the server-side state for one CMP enrollment
// transaction, keyed by the hex-encoded transactionID from the PKIHeader.
//
// Full lifecycle:
//   - Sync issuance (default): the row is inserted directly with State=ISSUED
//     and CertDER populated. It persists through certConf → CONFIRMED, and
//     optionally through revocation → REVOKED.
//   - Async issuance (RFC 9483 §4.4): the row is inserted with State=PENDING
//     and empty CertDER. A background worker calls LWCEnroll/LWCReenroll,
//     populates CertDER and transitions to ISSUED (or sets ErrorMessage and
//     transitions to ISSUE_FAILED). The EE retrieves the cert via pollReq.
//
// Terminal states (CONFIRMED, REVOKED) are retained for audit visibility and
// are NOT subject to TTL-based deletion.
type CMPTransaction struct {
	// TransactionID is the hex-encoded bytes from the CMP PKIHeader transactionID
	// field. Used as PRIMARY KEY; uniqueness enforced at DB level.
	TransactionID string
	// DMSID is the DMS this enrollment belongs to (path param from the request).
	DMSID string
	// CertSerialNumber is the hex-encoded serial number of the issued cert,
	// extracted from CertDER at insertion time. Stored as a denormalized column
	// to allow efficient lookup when a revocation arrives by serial.
	// Empty when State == PENDING.
	CertSerialNumber string
	// Certificate is the issued certificate that the client must confirm.
	// Stored so the server can verify the certHash in certConf.
	// Nil when State == PENDING.
	Certificate *models.X509Certificate
	// SentNonce is the hex-encoded senderNonce placed in the server's IP/CP/KUP response.
	// The client echoes it back as recipNonce in certConf; the server checks
	// they match (RFC 4210 §5.1.1).
	SentNonce string
	// ReceivedNonce is the hex-encoded senderNonce from the EE's initiating
	// request (ir/cr/kur). The certConf MUST carry a *fresh* senderNonce, so the
	// server rejects a certConf that reuses this value (RFC 9483 §3.1
	// badSenderNonce). Empty for legacy rows written before this was tracked.
	ReceivedNonce string
	// SupersededCertSerial is, for key-update (kur) transactions, the hex serial
	// number of the certificate being updated (the request's protection cert).
	// While this transaction is ISSUED-but-unconfirmed, that certificate must
	// not start further operations (RFC 9483 §4.1.3) — see
	// HasUnconfirmedReenrollment. Empty for ir/cr transactions and for
	// unprotected (NO_AUTH) key updates.
	SupersededCertSerial string
	// RegToken is the RFC 4211 §6.1 id-regCtrl-regToken value carried by the
	// request's CertRequest controls, when present. Empty when the request
	// supplied none. Used to enforce one-time use — see HasSeenRegToken.
	RegToken string
	// PopoChallenge is the hex-encoded expected Rand.int value for an ir/cr
	// transaction PENDING a challengeResp proof-of-possession round trip
	// (RFC 4210bis §5.2.8.3, popdecc/popdecr). Empty for every other
	// transaction, including phased-workflow PENDING rows.
	PopoChallenge string
	// State is the lifecycle state of this transaction; see CMPTransactionState.
	State CMPTransactionState
	// ErrorMessage holds the CA failure reason when State == ISSUE_FAILED.
	// Empty otherwise.
	ErrorMessage string
	// CSR is the certificate request built from the EE's CertTemplate.
	// Populated only when State == PENDING so the async worker can re-issue
	// the call to LWCEnroll/LWCReenroll without keeping the original PKIMessage.
	// Nil when State == ISSUED (the cert is stored instead).
	CSR *models.X509CertificateRequest
	// IsReenrollment is true when the original request was kur (re-enrollment),
	// false for ir/cr. The async worker uses this to choose LWCReenroll vs LWCEnroll.
	IsReenrollment bool
	// RequestType is the CMP body type that initiated the transaction: "ir"
	// (Initialization Request), "cr" (Certification Request), or "kur" (Key
	// Update Request). IsReenrollment is derivable from this ("kur" → true);
	// RequestType is the finer-grained record used by the UI to surface
	// whether a first-time enrollment was an ir or cr.
	RequestType string
	// SubjectCommonName is the CommonName from the enrollment request's
	// CertTemplate (i.e. the device ID). Stored at insertion time so the
	// management UI can render device-keyed transaction listings without
	// reparsing the cert DER.
	SubjectCommonName string
	// WFXJobID is the UUID of the WFX job that mirrors this CMP transaction.
	// Empty when WFX integration is disabled, when the transaction did not
	// reach a state with a known device CN, or when the WFX side rejected
	// the create call. The management UI uses it to deep-link transaction
	// rows to the corresponding workflow.
	WFXJobID string
	// ConfirmedAt records when the certConf was received and validated. Zero
	// value for non-confirmed transactions.
	ConfirmedAt time.Time
	// ExpiresAt is the absolute deadline after which the transaction is
	// considered stale and eligible for deletion. Only applies to in-flight
	// states (PENDING, ISSUED, ISSUE_FAILED). Terminal states ignore this.
	ExpiresAt time.Time
	// CreatedAt records when the transaction was first persisted.
	CreatedAt time.Time
}

// CMPTransactionRepo is the persistence interface for CMP enrollment transactions.
//
// Transactions progress through the following states:
//
//	PENDING → ISSUED → CONFIRMED → (optionally) REVOKED
//	                → ISSUE_FAILED
//
// Terminal states (CONFIRMED, REVOKED, ISSUE_FAILED) are retained indefinitely
// for audit visibility; only in-flight states (PENDING, ISSUED) are subject to
// TTL-based expiration.
type CMPTransactionRepo interface {
	// Exists reports whether an active (non-expired, non-terminal) transaction
	// with the given hex transactionID is present. It is a read-only check
	// used to reject replayed requests before any enrollment side-effects occur.
	Exists(ctx context.Context, transactionID string) (bool, error)

	// HasUnconfirmedReenrollment reports whether an active (ISSUED, non-expired)
	// re-enrollment (kur) transaction exists that is updating the certificate
	// with the given hex serial number (SupersededCertSerial) under the DMS.
	// Used to reject further operations with that certificate — a second KUR,
	// a new enrollment, a revocation — while its update is still awaiting
	// certConf (RFC 9483 §4.1.3). Scoped to the certificate rather than the
	// device CN because multiple certificates can legitimately share a subject
	// (one CN may be re-enrolled repeatedly); it is the *certificate under
	// update* that is locked, not the whole identity. Returns false once the
	// prior transaction has been confirmed (CONFIRMED), rolled back on timeout
	// (REVOKED), or has otherwise expired.
	HasUnconfirmedReenrollment(ctx context.Context, dmsID, supersededCertSerial string) (bool, error)

	// HasAbandonedReenrollment reports whether a re-enrollment (kur)
	// transaction that was updating the certificate with the given hex serial
	// number (SupersededCertSerial) under the DMS was abandoned: issued but
	// never confirmed and then rolled back on confirmation timeout (state
	// REVOKED). It is the post-timeout counterpart of HasUnconfirmedReenrollment
	// (which covers the still-pending window). The ir/cr enrollment path uses it
	// to force a device that abandoned a key-update to recover via a new kur
	// rather than an initialization/certification request (RFC 9483 §4.1.3,
	// sec-awareness). Scoped to the certificate, not the device CN.
	HasAbandonedReenrollment(ctx context.Context, dmsID, supersededCertSerial string) (bool, error)

	// HasSeenRegToken reports whether a transaction already exists under the
	// DMS carrying the given RFC 4211 §6.1 id-regCtrl-regToken value (the
	// CMPTransaction.RegToken field). regToken is intended for one-time use —
	// once a request presenting a given value has been accepted, any later
	// request presenting the same value must be rejected — so the check spans
	// every state (including REVOKED/CONFIRMED), not just active rows. Returns
	// false when regToken is empty.
	HasSeenRegToken(ctx context.Context, dmsID, regToken string) (bool, error)

	// Insert persists a new transaction.
	// Returns ErrCMPTransactionAlreadyExists when a live transaction with the
	// same transactionID already exists, enabling replay-attack prevention
	// (RFC 4210 §5.1.1 transactionIdInUse).
	Insert(ctx context.Context, tx CMPTransaction) error

	// Select reads a transaction by its hex transactionID without modifying it.
	// Used by pollReq, which may be called multiple times on the same row.
	// Returns (zero, false, nil) when the transactionID is not found or has
	// already expired (for in-flight states).
	Select(ctx context.Context, transactionID string) (CMPTransaction, bool, error)

	// SelectIncludingExpired returns the transaction row regardless of expiry
	// or terminal state. Used by error-reporting paths (e.g. handleCertConf)
	// to distinguish "transaction never existed" from "transaction is past
	// ExpiresAt but not yet swept by the monitor" so the CMP error message
	// can carry the accurate reason and PKIFailureInfo bit.
	SelectIncludingExpired(ctx context.Context, transactionID string) (CMPTransaction, bool, error)

	// SelectAndDelete atomically fetches and removes a transaction by its hex
	// transactionID. Retained for backward-compat but should be replaced by
	// Confirm in new code paths.
	SelectAndDelete(ctx context.Context, transactionID string) (CMPTransaction, bool, error)

	// Confirm atomically transitions a transaction from ISSUED to CONFIRMED,
	// recording the confirmation timestamp. The returned priorState is the
	// state the row was in BEFORE the update was attempted (or empty when no
	// row exists), letting callers distinguish:
	//   - (row, ISSUED, true,  nil) → transition succeeded
	//   - (zero, REVOKED,  false, nil) → row was already revoked (race with
	//                                    the confirmation monitor; the cert
	//                                    is no longer valid on the wire)
	//   - (zero, CONFIRMED,false, nil) → row was already confirmed (idempotent
	//                                    replay of certConf is allowed)
	//   - (zero, "",       false, nil) → row not found
	//   - (zero, "",       false, err) → DB error
	// This signature is what the CMP controller uses to close the
	// handleCertConf-vs-confirmation-monitor split-brain race described in the
	// audit (cmp.go: handleCertConf, handlePoll implicit-confirm).
	Confirm(ctx context.Context, transactionID string) (CMPTransaction, CMPTransactionState, bool, error)

	// UpdateState transitions a transaction's State (and, when ISSUED, its
	// certificate) atomically, and re-bases ExpiresAt to the supplied
	// deadline. errorMessage is recorded on ISSUE_FAILED transitions.
	//
	// The update is keyed only by transactionID — staleness is NOT filtered
	// here because two callers explicitly need to write past-expiry rows:
	// the confirmation monitor transitions expired PENDING rows to
	// ISSUE_FAILED for audit, and the admin approval path can race the
	// monitor by a few ms across the original deadline (rejecting would
	// orphan an already-issued cert). Service-layer callers that need a
	// staleness precondition MUST enforce it before calling UpdateState.
	//
	// Returns (true, nil) when a row was updated, (false, nil) when no row
	// exists with the given transactionID, (false, err) on any DB error.
	UpdateState(ctx context.Context, transactionID string, state CMPTransactionState, cert *models.X509Certificate, errorMessage string, expiresAt time.Time) (bool, error)

	// MarkRevokedByCertSerial transitions any CONFIRMED transaction with the
	// given certificate serial number to REVOKED. This is called after a
	// successful CMP revocation request so the UI can show the full lifecycle.
	// No-op if no matching transaction is found.
	MarkRevokedByCertSerial(ctx context.Context, certSerialNumber string) error

	// SelectByCertSerial returns the transaction that issued the certificate
	// with the given hex serial number, regardless of state or expiry.
	// Used by the enrollment paths to classify a non-active protection
	// certificate: when the transaction that issued the device's current
	// active cert is a confirmed key update (kur), the superseded cert can no
	// longer authenticate (RFC 9483 §4.1.3 → certRevoked); a cert superseded
	// by a plain replaceable re-enrollment stays usable.
	// Returns (zero, false, nil) when no transaction references the serial.
	SelectByCertSerial(ctx context.Context, certSerialNumber string) (CMPTransaction, bool, error)

	// SelectExpiredIssued returns up to `limit` transactions in ISSUED state
	// whose ExpiresAt is in the past, oldest first. The CMP confirmation
	// monitor uses this to find certificates that were issued but never
	// confirmed by the EE within the window the DMS allows; those certs
	// are revoked at the CA layer and the row is then transitioned via
	// MarkRevokedByTransactionID for audit visibility.
	SelectExpiredIssued(ctx context.Context, limit int) ([]CMPTransaction, error)

	// MarkRevokedByTransactionID transitions a transaction (in any state) to
	// REVOKED, keyed by its hex transactionID. Used by the confirmation
	// monitor after it revokes the underlying certificate at the CA, so the
	// row persists in REVOKED state for audit. No-op if the row is not found.
	MarkRevokedByTransactionID(ctx context.Context, transactionID string) error

	// SelectPending returns up to `limit` PENDING transactions whose ExpiresAt
	// is in the future, oldest first. The async worker uses this to find rows
	// it must process. Returns an empty slice when no work is queued.
	SelectPending(ctx context.Context, limit int) ([]CMPTransaction, error)

	// SelectExpiredPending returns up to `limit` PENDING transactions whose
	// ExpiresAt has already elapsed, oldest first. The CMP confirmation
	// monitor uses this to find phased-workflow requests an administrator
	// never acted on; those rows are transitioned to ISSUE_FAILED with a
	// reason via UpdateState so pollReq can surface the cause to the EE
	// and the operator retains an audit trail.
	SelectExpiredPending(ctx context.Context, limit int) ([]CMPTransaction, error)

	// DeleteExpired removes ISSUE_FAILED transactions whose ExpiresAt is in
	// the past — that is, rows that have already been transitioned to a
	// non-fatal failure state and have outlived their retention window.
	// PENDING rows are intentionally NOT deleted here: when their approval
	// window elapses they are transitioned to ISSUE_FAILED (with a fresh
	// retention TTL) by the confirmation monitor so the rejection is visible
	// to operators and to subsequent pollReqs. Terminal states (CONFIRMED,
	// REVOKED) and live ISSUED rows are likewise untouched.
	// Should be called periodically by a background goroutine.
	DeleteExpired(ctx context.Context) error

	// SelectAllByDMS streams every transaction belonging to the given DMS,
	// honouring the standard query parameters (pagination, sort, filter). The
	// applyFunc is invoked once per row in result order; the returned bookmark
	// identifies the next page (empty when the cursor is exhausted). When
	// exhaustiveRun is true the repo iterates all pages internally and only
	// returns once every matching row has been delivered.
	//
	// This method returns ALL states (including terminal CONFIRMED/REVOKED)
	// so the management UI can display both active and completed transactions.
	SelectAllByDMS(ctx context.Context, dmsID string, exhaustiveRun bool, applyFunc func(CMPTransaction), queryParams *resources.QueryParameters) (string, error)
}

type DMSRepo interface {
	Count(ctx context.Context) (int, error)
	CountWithFilters(ctx context.Context, queryParams *resources.QueryParameters) (int, error)
	SelectAll(ctx context.Context, exhaustiveRun bool, applyFunc func(models.DMS), queryParams *resources.QueryParameters, extraOpts map[string]any) (string, error)
	SelectExists(ctx context.Context, ID string) (bool, *models.DMS, error)
	Update(ctx context.Context, dms *models.DMS) (*models.DMS, error)
	Insert(ctx context.Context, dms *models.DMS) (*models.DMS, error)
	Delete(ctx context.Context, ID string) error
}
