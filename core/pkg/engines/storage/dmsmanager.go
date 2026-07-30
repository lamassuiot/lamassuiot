package storage

import (
	"context"
	"time"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
)

// CMPTransactionRepo is the persistence interface for CMP enrollment
// transactions (see models.CMPTransaction and models.CMPTransactionState for
// the data model).
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
	Insert(ctx context.Context, tx models.CMPTransaction) error

	// Select reads a transaction by its hex transactionID without modifying it.
	// Used by pollReq, which may be called multiple times on the same row.
	// Returns (zero, false, nil) when the transactionID is not found or has
	// already expired (for in-flight states).
	Select(ctx context.Context, transactionID string) (models.CMPTransaction, bool, error)

	// SelectIncludingExpired returns the transaction row regardless of expiry
	// or terminal state. Used by error-reporting paths (e.g. handleCertConf)
	// to distinguish "transaction never existed" from "transaction is past
	// ExpiresAt but not yet swept by the monitor" so the CMP error message
	// can carry the accurate reason and PKIFailureInfo bit.
	SelectIncludingExpired(ctx context.Context, transactionID string) (models.CMPTransaction, bool, error)

	// SelectAndDelete atomically fetches and removes a transaction by its hex
	// transactionID. Retained for backward-compat but should be replaced by
	// Confirm in new code paths.
	SelectAndDelete(ctx context.Context, transactionID string) (models.CMPTransaction, bool, error)

	// ClaimPending atomically transitions a transaction from PENDING to the
	// transient APPROVING state, conditioned on the row still being PENDING
	// and not yet expired, and returns the claimed row. This is the
	// concurrency primitive behind admin approval/rejection of a
	// phased-workflow transaction (see ApproveCMPTransaction /
	// RejectCMPTransaction): only one of several concurrent callers (a
	// double-clicked approve, a client retry, or a race between approve and
	// reject) can win the claim, so exactly one certificate is ever issued
	// for a given PENDING row. A caller that fails to claim (returns false)
	// MUST treat the transaction as no longer actionable rather than
	// retrying the underlying CA operation.
	//
	// Returns (row, true, nil) when the claim succeeded, (zero, false, nil)
	// when the row does not exist, is not PENDING, or has expired, and
	// (zero, false, err) on a DB error.
	ClaimPending(ctx context.Context, transactionID string) (models.CMPTransaction, bool, error)

	// WithDeviceLock runs fn while holding a cross-replica mutual-exclusion
	// lock scoped to deviceID (a Postgres advisory lock held for the
	// transaction's lifetime; on dialects without one, e.g. SQLite, fn just
	// runs directly — a single writer already serializes access there). It
	// closes TOCTOU races on per-device policy checks that must remain valid
	// across a call to an external service (e.g. re-checking
	// CR.MaximumActiveCertificates against the CA immediately before
	// SignCertificate, so two concurrent cr requests for the same device
	// cannot both observe "under the cap" and both issue). Returns fn's
	// error, or a lock-acquisition error.
	WithDeviceLock(ctx context.Context, deviceID string, fn func(ctx context.Context) error) error

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
	Confirm(ctx context.Context, transactionID string) (models.CMPTransaction, models.CMPTransactionState, bool, error)

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
	UpdateState(ctx context.Context, transactionID string, state models.CMPTransactionState, cert *models.X509Certificate, errorMessage string, expiresAt time.Time) (bool, error)

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
	SelectByCertSerial(ctx context.Context, certSerialNumber string) (models.CMPTransaction, bool, error)

	// SelectExpiredIssued returns up to `limit` transactions in ISSUED or
	// REVOKING state whose ExpiresAt is in the past, oldest first (REVOKING
	// rows are included so a monitor crash between ClaimIssuedForRevocation
	// and the final CA call/state write doesn't strand a row outside every
	// sweep). The CMP confirmation monitor uses this to find certificates
	// that were issued but never confirmed by the EE within the window the
	// DMS allows; those certs are revoked at the CA layer (after first
	// claiming the row via ClaimIssuedForRevocation) and the row is then
	// transitioned via MarkRevokedByTransactionID for audit visibility.
	SelectExpiredIssued(ctx context.Context, limit int) ([]models.CMPTransaction, error)

	// ClaimIssuedForRevocation atomically transitions a transaction from
	// ISSUED to the transient REVOKING state, conditioned on the row still
	// being ISSUED, and returns the claimed row. This is the concurrency
	// primitive behind the confirmation-timeout monitor's revocation of an
	// expired, unconfirmed transaction: it closes the race where a
	// legitimate certConf (or implicit-confirm pollReq, both of which use
	// Confirm — ISSUED → CONFIRMED) arrives at the same moment the monitor
	// decides the row timed out. Confirm and ClaimIssuedForRevocation both
	// require state=ISSUED, so only one side of that race can ever win; the
	// loser (here, the monitor) MUST skip revoking the certificate rather
	// than proceeding — the row is no longer eligible.
	//
	// Returns (row, true, nil) when the claim succeeded, (zero, false, nil)
	// when the row does not exist or is not ISSUED, and (zero, false, err)
	// on a DB error.
	ClaimIssuedForRevocation(ctx context.Context, transactionID string) (models.CMPTransaction, bool, error)

	// MarkRevokedByTransactionID transitions a transaction (in any state) to
	// REVOKED, keyed by its hex transactionID. Used by the confirmation
	// monitor after it revokes the underlying certificate at the CA, so the
	// row persists in REVOKED state for audit. No-op if the row is not found.
	MarkRevokedByTransactionID(ctx context.Context, transactionID string) error

	// SelectPending returns up to `limit` PENDING transactions whose ExpiresAt
	// is in the future, oldest first. The async worker uses this to find rows
	// it must process. Returns an empty slice when no work is queued.
	SelectPending(ctx context.Context, limit int) ([]models.CMPTransaction, error)

	// SelectExpiredPending returns up to `limit` PENDING or APPROVING
	// transactions whose ExpiresAt has already elapsed, oldest first. The
	// CMP confirmation monitor uses this to find phased-workflow requests an
	// administrator never acted on (PENDING) or started acting on but never
	// finished, e.g. a crash between ClaimPending and the final state write
	// (APPROVING); those rows are transitioned to ISSUE_FAILED with a reason
	// via UpdateState so pollReq can surface the cause to the EE and the
	// operator retains an audit trail.
	SelectExpiredPending(ctx context.Context, limit int) ([]models.CMPTransaction, error)

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
	SelectAllByDMS(ctx context.Context, dmsID string, exhaustiveRun bool, applyFunc func(models.CMPTransaction), queryParams *resources.QueryParameters) (string, error)
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
