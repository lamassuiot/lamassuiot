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
	// recording the confirmation timestamp. Returns the row and true if the
	// transition succeeded; (zero, false, nil) if the row was not found or
	// was not in ISSUED state.
	Confirm(ctx context.Context, transactionID string) (CMPTransaction, bool, error)

	// UpdateState transitions a transaction's State (and, when ISSUED, its
	// CertDER) atomically. Used by the async-issuance worker to record the
	// outcome of LWCEnroll. errorMessage is ignored when state != ISSUE_FAILED.
	// Returns nil even if the row was already deleted (e.g., by DeleteExpired
	// racing the worker); the caller treats that as a no-op.
	UpdateState(ctx context.Context, transactionID string, state CMPTransactionState, cert *models.X509Certificate, errorMessage string) error

	// MarkRevokedByCertSerial transitions any CONFIRMED transaction with the
	// given certificate serial number to REVOKED. This is called after a
	// successful CMP revocation request so the UI can show the full lifecycle.
	// No-op if no matching transaction is found.
	MarkRevokedByCertSerial(ctx context.Context, certSerialNumber string) error

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

	// DeleteExpired removes in-flight transactions (PENDING, ISSUED,
	// ISSUE_FAILED) whose ExpiresAt is in the past. Terminal states
	// (CONFIRMED, REVOKED) are never deleted by this method.
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
