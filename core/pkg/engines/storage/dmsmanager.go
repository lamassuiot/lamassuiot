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
)

// CMPTransaction holds the server-side state for one in-flight CMP enrollment
// transaction, keyed by the hex-encoded transactionID from the PKIHeader.
//
// Two lifecycles are supported:
//   - Sync issuance (default): the row is inserted directly with State=ISSUED
//     and CertDER populated. It exists between the IP/CP/KUP response and the
//     EE's certConf, or until ExpiresAt.
//   - Async issuance (RFC 9483 §4.4): the row is inserted with State=PENDING
//     and empty CertDER. A background worker calls LWCEnroll/LWCReenroll,
//     populates CertDER and transitions to ISSUED (or sets ErrorMessage and
//     transitions to ISSUE_FAILED). The EE retrieves the cert via pollReq.
type CMPTransaction struct {
	// TransactionID is the hex-encoded bytes from the CMP PKIHeader transactionID
	// field. Used as PRIMARY KEY; uniqueness enforced at DB level.
	TransactionID string
	// DMSID is the DMS this enrollment belongs to (path param from the request).
	DMSID string
	// CertDER is the raw DER of the issued certificate that the client must
	// confirm. Stored so the server can verify the certHash in certConf.
	// Empty when State == PENDING.
	CertDER []byte
	// SentNonce is the senderNonce placed in the server's IP/CP/KUP response.
	// The client echoes it back as recipNonce in certConf; the server checks
	// they match (RFC 4210 §5.1.1).
	SentNonce []byte
	// State is the lifecycle state of this transaction; see CMPTransactionState.
	State CMPTransactionState
	// ErrorMessage holds the CA failure reason when State == ISSUE_FAILED.
	// Empty otherwise.
	ErrorMessage string
	// CSRDER is the DER-encoded PKCS#10 CSR built from the EE's CertTemplate.
	// Populated only when State == PENDING so the async worker can re-issue
	// the call to LWCEnroll/LWCReenroll without keeping the original PKIMessage.
	// Empty when State == ISSUED (the cert is stored instead).
	CSRDER []byte
	// IsReenrollment is true when the original request was kur (re-enrollment),
	// false for ir/cr. The async worker uses this to choose LWCReenroll vs LWCEnroll.
	IsReenrollment bool
	// ExpiresAt is the absolute deadline after which the transaction is
	// considered stale and eligible for deletion. Derived from the DMS's
	// confirmation_timeout setting, defaulting to 5 minutes.
	ExpiresAt time.Time
	// CreatedAt records when the transaction was first persisted.
	CreatedAt time.Time
}

// CMPTransactionRepo is the persistence interface for CMP in-flight transactions.
//
// Because CMP transaction state is ephemeral protocol data (not business domain
// data), the interface is intentionally minimal: no pagination, filtering, or
// statistics — just the operations the CMP controller and async worker need.
type CMPTransactionRepo interface {
	// Exists reports whether a non-expired transaction with the given hex
	// transactionID is present. It is a read-only check used to reject
	// replayed requests before any enrollment side-effects occur.
	Exists(ctx context.Context, transactionID string) (bool, error)

	// Insert persists a new transaction.
	// Returns ErrCMPTransactionAlreadyExists when a live transaction with the
	// same transactionID already exists, enabling replay-attack prevention
	// (RFC 4210 §5.1.1 transactionIdInUse).
	Insert(ctx context.Context, tx CMPTransaction) error

	// Select reads a transaction by its hex transactionID without deleting it.
	// Used by pollReq, which may be called multiple times on the same row.
	// Returns (zero, false, nil) when the transactionID is not found or has
	// already expired.
	Select(ctx context.Context, transactionID string) (CMPTransaction, bool, error)

	// SelectAndDelete atomically fetches and removes a transaction by its hex
	// transactionID. The deletion is unconditional — whether the certConf is
	// accepted or rejected, the transaction is spent. Returns (zero, false, nil)
	// when the transactionID is not found or has already expired.
	SelectAndDelete(ctx context.Context, transactionID string) (CMPTransaction, bool, error)

	// UpdateState transitions a transaction's State (and, when ISSUED, its
	// CertDER) atomically. Used by the async-issuance worker to record the
	// outcome of LWCEnroll. errorMessage is ignored when state != ISSUE_FAILED.
	// Returns nil even if the row was already deleted (e.g., by DeleteExpired
	// racing the worker); the caller treats that as a no-op.
	UpdateState(ctx context.Context, transactionID string, state CMPTransactionState, certDER []byte, errorMessage string) error

	// SelectPending returns up to `limit` PENDING transactions whose ExpiresAt
	// is in the future, oldest first. The async worker uses this to find rows
	// it must process. Returns an empty slice when no work is queued.
	SelectPending(ctx context.Context, limit int) ([]CMPTransaction, error)

	// DeleteExpired removes all transactions whose ExpiresAt is in the past.
	// Should be called periodically (e.g., every confirmation_timeout interval)
	// by a background goroutine in the controller.
	DeleteExpired(ctx context.Context) error
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
