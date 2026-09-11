package postgres

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// cmpTransactionRow is the GORM model that maps to the cmp_transactions table.
// It is intentionally kept private; callers use the domain type models.CMPTransaction.
type cmpTransactionRow struct {
	TransactionID        string `gorm:"primaryKey;column:transaction_id"`
	DMSID                string `gorm:"column:dms_id;not null"`
	CertSerialNumber     string `gorm:"column:cert_serial_number;not null;default:''"`
	Certificate          string `gorm:"column:certificate"`                                // base64-PEM text; empty for PENDING rows
	SentNonce            string `gorm:"column:sent_nonce;not null;default:''"`             // hex-encoded bytes
	ReceivedNonce        string `gorm:"column:received_nonce;not null;default:''"`         // hex-encoded request senderNonce
	SupersededCertSerial string `gorm:"column:superseded_cert_serial;not null;default:''"` // kur: hex serial of the cert being updated
	RegToken             string `gorm:"column:reg_token;not null;default:''"`              // RFC 4211 §6.1 id-regCtrl-regToken, one-time use
	PopoChallenge        string `gorm:"column:popo_challenge;not null;default:''"`         // challengeResp POP: hex expected Rand.int
	State                string `gorm:"column:state;not null;default:ISSUED"`
	ErrorMessage         string `gorm:"column:error_message;not null;default:''"`
	CSR                  string `gorm:"column:csr"` // base64-PEM text; empty for ISSUED rows
	IsReenrollment       bool   `gorm:"column:is_reenrollment;not null;default:false"`
	CentralKeyGeneration bool   `gorm:"column:central_key_generation;not null;default:false"` // RFC 9483 §4.1.6 CKG: response not replayable
	RequestType          string `gorm:"column:request_type;not null;default:''"`
	// POPOMethod/ChallengeType/AuthenticatorControlPresent/AuthModeAtEnrollment
	// are security-audit metadata recording how this transaction's key
	// possession and requester identity were established — see the doc
	// comments on the corresponding models.CMPTransaction fields.
	POPOMethod                  string    `gorm:"column:popo_method;not null;default:''"`
	ChallengeType               string    `gorm:"column:challenge_type;not null;default:''"`
	AuthenticatorControlPresent bool      `gorm:"column:authenticator_control_present;not null;default:false"`
	AuthModeAtEnrollment        string    `gorm:"column:auth_mode_at_enrollment;not null;default:''"`
	SubjectCommonName           string    `gorm:"column:subject_common_name;not null;default:''"`
	WFXJobID                    string    `gorm:"column:wfx_job_id;not null;default:''"`
	ConfirmedAt                 time.Time `gorm:"column:confirmed_at"`
	ExpiresAt                   time.Time `gorm:"column:expires_at;not null"`
	CreatedAt                   time.Time `gorm:"column:created_at;autoCreateTime"`
}

func certToString(c *models.X509Certificate) string {
	if c == nil {
		return ""
	}
	return c.String()
}

func stringToCert(s string) *models.X509Certificate {
	if s == "" {
		return nil
	}
	var c models.X509Certificate
	if err := c.Scan(s); err != nil {
		return nil
	}
	return &c
}

func csrToString(c *models.X509CertificateRequest) string {
	if c == nil {
		return ""
	}
	return c.String()
}

func stringToCSR(s string) *models.X509CertificateRequest {
	if s == "" {
		return nil
	}
	var c models.X509CertificateRequest
	if err := c.Scan(s); err != nil {
		return nil
	}
	return &c
}

func (cmpTransactionRow) TableName() string { return "cmp_transactions" }

// cmpRegTokenClaimRow records a claimed one-time-use regToken. It is a separate
// table from cmp_transactions on purpose: the claim must be written BEFORE
// issuance (so concurrent requests cannot both pass the one-time-use check),
// whereas a transaction row is only written after issuance because it carries the
// issued certificate. The composite primary key is what makes the claim atomic.
type cmpRegTokenClaimRow struct {
	DMSID     string    `gorm:"primaryKey;column:dms_id"`
	RegToken  string    `gorm:"primaryKey;column:reg_token"`
	ClaimedAt time.Time `gorm:"column:claimed_at;not null"`
}

func (cmpRegTokenClaimRow) TableName() string { return "cmp_reg_token_claims" }

// PostgresCMPTransactionStorage implements storage.CMPTransactionRepo using Postgres.
type PostgresCMPTransactionStorage struct {
	db      *gorm.DB
	logger  *logrus.Entry
	querier *DBQuerier[cmpTransactionRow]
	// deviceLocks backs WithDeviceLock on dialects without advisory locks.
	deviceLocks deviceLockTable
}

// NewCMPTransactionRepository creates a PostgresCMPTransactionStorage backed by
// the provided *gorm.DB. The caller is responsible for ensuring the
// cmp_transactions table exists (via the goose migration).
func NewCMPTransactionRepository(logger *logrus.Entry, db *gorm.DB) (storage.CMPTransactionRepo, error) {
	// Generic querier used only for the management-facing SelectAllByDMS path;
	// the protocol-facing methods continue to use direct GORM operations so
	// their RFC-driven semantics stay legible inline.
	querier, err := TableQuery(logger, db, "cmp_transactions", "transaction_id", cmpTransactionRow{})
	if err != nil {
		return nil, err
	}
	return &PostgresCMPTransactionStorage{db: db, logger: logger, querier: querier}, nil
}

// Exists reports whether an active (non-expired, non-terminal) transaction
// with the given hex transactionID is present. Terminal states (CONFIRMED,
// REVOKED) are excluded so a transactionID can be reused after completion.
//
// The expires_at comparison uses the database-side clock (NOW()) rather than
// the application clock, so multiple concurrent requests see a consistent
// notion of "expired" even under NTP slew or VM-clock correction.
func (s *PostgresCMPTransactionStorage) Exists(ctx context.Context, transactionID string) (bool, error) {
	var count int64
	result := s.db.WithContext(ctx).
		Model(&cmpTransactionRow{}).
		Where("transaction_id = ? AND expires_at > "+nowExpr(s.db)+" AND state IN (?,?)",
			transactionID,
			string(models.CMPTransactionStatePending),
			string(models.CMPTransactionStateIssued),
		).
		Count(&count)
	if result.Error != nil {
		s.logger.Errorf("cmp_transactions: exists %s: %v", transactionID, result.Error)
		return false, result.Error
	}
	return count > 0, nil
}

// HasUnconfirmedReenrollment reports whether an active (ISSUED, non-expired)
// re-enrollment transaction is updating the certificate with the given hex
// serial under the DMS. Scoped to the superseded certificate — not the device
// CN — because one subject may hold several certificates over time; only the
// specific certificate under update is locked (RFC 9483 §4.1.3). See the
// CMPTransactionRepo interface doc.
func (s *PostgresCMPTransactionStorage) HasUnconfirmedReenrollment(ctx context.Context, dmsID, supersededCertSerial string) (bool, error) {
	if supersededCertSerial == "" {
		// Unprotected (NO_AUTH) key updates record no superseded serial; there
		// is nothing to lock on.
		return false, nil
	}
	var count int64
	result := s.db.WithContext(ctx).
		Model(&cmpTransactionRow{}).
		Where("dms_id = ? AND superseded_cert_serial = ? AND is_reenrollment = ? AND state = ? AND expires_at > "+nowExpr(s.db),
			dmsID,
			supersededCertSerial,
			true,
			string(models.CMPTransactionStateIssued),
		).
		Count(&count)
	if result.Error != nil {
		s.logger.Errorf("cmp_transactions: has-unconfirmed-reenrollment dms=%s superseded=%s: %v", dmsID, supersededCertSerial, result.Error)
		return false, result.Error
	}
	return count > 0, nil
}

// HasAbandonedReenrollment reports whether a re-enrollment (kur) transaction
// updating the certificate with the given hex serial (SupersededCertSerial)
// under the DMS was abandoned — issued but never confirmed and rolled back to
// REVOKED on confirmation timeout. It is the post-timeout counterpart of
// HasUnconfirmedReenrollment. See the CMPTransactionRepo interface doc.
func (s *PostgresCMPTransactionStorage) HasAbandonedReenrollment(ctx context.Context, dmsID, supersededCertSerial string) (bool, error) {
	if supersededCertSerial == "" {
		return false, nil
	}
	var count int64
	result := s.db.WithContext(ctx).
		Model(&cmpTransactionRow{}).
		Where("dms_id = ? AND superseded_cert_serial = ? AND is_reenrollment = ? AND state = ?",
			dmsID,
			supersededCertSerial,
			true,
			string(models.CMPTransactionStateRevoked),
		).
		Count(&count)
	if result.Error != nil {
		s.logger.Errorf("cmp_transactions: has-abandoned-reenrollment dms=%s superseded=%s: %v", dmsID, supersededCertSerial, result.Error)
		return false, result.Error
	}
	return count > 0, nil
}

// HasSeenRegToken reports whether any transaction under the DMS already
// carries the given regToken value. Unlike HasUnconfirmedReenrollment, this
// spans every state — a token is one-time-use for the lifetime of the DMS,
// not just while the original transaction is in flight (RFC 4211 §6.1).
func (s *PostgresCMPTransactionStorage) HasSeenRegToken(ctx context.Context, dmsID, regToken string) (bool, error) {
	if regToken == "" {
		return false, nil
	}
	var count int64
	result := s.db.WithContext(ctx).
		Model(&cmpTransactionRow{}).
		Where("dms_id = ? AND reg_token = ?", dmsID, regToken).
		Count(&count)
	if result.Error != nil {
		s.logger.Errorf("cmp_transactions: has-seen-reg-token dms=%s: %v", dmsID, result.Error)
		return false, result.Error
	}
	return count > 0, nil
}

// ClaimRegToken implements storage.CMPTransactionRepo. The claim is an INSERT
// into a dedicated table whose primary key is (dms_id, reg_token), so exactly
// one concurrent caller can win: ON CONFLICT DO NOTHING makes the loser's
// RowsAffected zero rather than raising.
func (s *PostgresCMPTransactionStorage) ClaimRegToken(ctx context.Context, dmsID, regToken string) (bool, error) {
	if regToken == "" {
		return true, nil
	}
	claim := cmpRegTokenClaimRow{
		DMSID:     dmsID,
		RegToken:  regToken,
		ClaimedAt: time.Now(),
	}
	result := s.db.WithContext(ctx).
		Clauses(clause.OnConflict{DoNothing: true}).
		Create(&claim)
	if result.Error != nil {
		s.logger.Errorf("cmp_reg_token_claims: claim dms=%s: %v", dmsID, result.Error)
		return false, result.Error
	}
	return result.RowsAffected > 0, nil
}

// SelectByCertSerial returns the transaction that issued the certificate with
// the given hex serial number, regardless of state or expiry. Rows are keyed
// by transaction_id, so at most one row references a given issued cert. See
// the CMPTransactionRepo interface doc for the superseded-cert classification
// this enables.
func (s *PostgresCMPTransactionStorage) SelectByCertSerial(ctx context.Context, certSerialNumber string) (models.CMPTransaction, bool, error) {
	var row cmpTransactionRow
	result := s.db.WithContext(ctx).
		Where("cert_serial_number = ?", certSerialNumber).
		First(&row)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return models.CMPTransaction{}, false, nil
		}
		s.logger.Errorf("cmp_transactions: select-by-cert-serial %s: %v", certSerialNumber, result.Error)
		return models.CMPTransaction{}, false, result.Error
	}
	return rowToDomain(row), true, nil
}

// nowExpr returns the SQL expression that yields "now" on the dialect of db.
// Postgres and MySQL use NOW(); SQLite (used in tests / monolithic dev mode)
// uses CURRENT_TIMESTAMP. Centralising this avoids application-side
// time.Now() being interleaved with database-evaluated expires_at, which is
// the root cause of the clock-skew TTL races flagged in the audit.
func nowExpr(db *gorm.DB) string {
	switch db.Dialector.Name() {
	case "sqlite":
		return "CURRENT_TIMESTAMP"
	default:
		return "NOW()"
	}
}

// Insert persists a new CMP transaction.
//
// It uses INSERT ... ON CONFLICT DO NOTHING to detect duplicate transactionIDs
// atomically.  If the row was not inserted (because a live row with the same
// primary key already exists), Insert returns errs.ErrCMPTransactionAlreadyExists
// so the controller can respond with PKIFailureInfo transactionIdInUse (21).
//
// The caller chooses the initial state by setting tx.State. Sync issuance sets
// ISSUED with Certificate populated; async issuance sets PENDING with CSR + the
// IsReenrollment flag so the worker can later finish issuance.
func (s *PostgresCMPTransactionStorage) Insert(ctx context.Context, tx models.CMPTransaction) error {
	state := tx.State
	if state == "" {
		// Backward-compatible default for callers that didn't yet set State.
		state = models.CMPTransactionStateIssued
	}
	row := cmpTransactionRow{
		TransactionID:               tx.TransactionID,
		DMSID:                       tx.DMSID,
		CertSerialNumber:            tx.CertSerialNumber,
		Certificate:                 certToString(tx.Certificate),
		SentNonce:                   tx.SentNonce,
		ReceivedNonce:               tx.ReceivedNonce,
		SupersededCertSerial:        tx.SupersededCertSerial,
		RegToken:                    tx.RegToken,
		PopoChallenge:               tx.PopoChallenge,
		State:                       string(state),
		ErrorMessage:                tx.ErrorMessage,
		CSR:                         csrToString(tx.CSR),
		IsReenrollment:              tx.IsReenrollment,
		CentralKeyGeneration:        tx.CentralKeyGeneration,
		RequestType:                 tx.RequestType,
		POPOMethod:                  tx.POPOMethod,
		ChallengeType:               tx.ChallengeType,
		AuthenticatorControlPresent: tx.AuthenticatorControlPresent,
		AuthModeAtEnrollment:        tx.AuthModeAtEnrollment,
		SubjectCommonName:           tx.SubjectCommonName,
		WFXJobID:                    tx.WFXJobID,
		ConfirmedAt:                 tx.ConfirmedAt,
		ExpiresAt:                   tx.ExpiresAt,
		CreatedAt:                   tx.CreatedAt,
	}

	// OnConflict(DoNothing) + RowsAffected==0 distinguishes a duplicate key
	// from other errors without needing a separate SELECT.
	result := s.db.WithContext(ctx).
		Clauses(clause.OnConflict{DoNothing: true}).
		Create(&row)

	if result.Error != nil {
		s.logger.Errorf("cmp_transactions: insert %s: %v", tx.TransactionID, result.Error)
		return result.Error
	}
	if result.RowsAffected == 0 {
		return errs.ErrCMPTransactionAlreadyExists
	}
	return nil
}

// Select reads a transaction by ID without modifying it. For in-flight states
// (PENDING, ISSUED) also checks expires_at; terminal states (CONFIRMED,
// REVOKED, ISSUE_FAILED) are always visible regardless of expiry.
func (s *PostgresCMPTransactionStorage) Select(ctx context.Context, transactionID string) (models.CMPTransaction, bool, error) {
	var row cmpTransactionRow
	result := s.db.WithContext(ctx).
		Where("transaction_id = ? AND (state IN (?,?,?) OR expires_at > "+nowExpr(s.db)+")",
			transactionID,
			string(models.CMPTransactionStateConfirmed),
			string(models.CMPTransactionStateRevoked),
			string(models.CMPTransactionStateIssueFailed),
		).
		First(&row)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return models.CMPTransaction{}, false, nil
		}
		s.logger.Errorf("cmp_transactions: select %s: %v", transactionID, result.Error)
		return models.CMPTransaction{}, false, result.Error
	}
	return rowToDomain(row), true, nil
}

// SelectIncludingExpired reads a transaction by ID with NO state or expiry
// filtering. Used by error-reporting paths that need to tell apart "row never
// existed" from "row past ExpiresAt but not yet swept by the monitor". Callers
// must not act on the returned row's contents for issuance decisions — Select
// is the right method for those.
func (s *PostgresCMPTransactionStorage) SelectIncludingExpired(ctx context.Context, transactionID string) (models.CMPTransaction, bool, error) {
	var row cmpTransactionRow
	result := s.db.WithContext(ctx).
		Where("transaction_id = ?", transactionID).
		First(&row)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return models.CMPTransaction{}, false, nil
		}
		s.logger.Errorf("cmp_transactions: select-any %s: %v", transactionID, result.Error)
		return models.CMPTransaction{}, false, result.Error
	}
	return rowToDomain(row), true, nil
}

// SelectAndDelete atomically fetches and deletes a transaction by its hex
// transactionID. Using DELETE ... RETURNING * is a single round-trip and fully
// atomic under Postgres's default READ COMMITTED isolation — no separate SELECT
// is needed, preventing TOCTOU races across concurrent server replicas.
//
// Expired rows are treated as non-existent: the caller sees (zero, false, nil).
func (s *PostgresCMPTransactionStorage) SelectAndDelete(ctx context.Context, transactionID string) (models.CMPTransaction, bool, error) {
	var row cmpTransactionRow
	result := s.db.WithContext(ctx).
		Raw(
			`DELETE FROM cmp_transactions
			  WHERE transaction_id = ? AND expires_at > `+nowExpr(s.db)+`
			  RETURNING *`,
			transactionID,
		).
		Scan(&row)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return models.CMPTransaction{}, false, nil
		}
		s.logger.Errorf("cmp_transactions: select-and-delete %s: %v", transactionID, result.Error)
		return models.CMPTransaction{}, false, result.Error
	}
	if result.RowsAffected == 0 {
		return models.CMPTransaction{}, false, nil
	}

	return rowToDomain(row), true, nil
}

// ClaimPending atomically transitions a transaction from PENDING to APPROVING,
// conditioned on the row still being PENDING and not expired, mirroring
// Confirm's conditional-update approach so admin approval/rejection gets the
// same concurrency guarantee certConf already has: only one of several
// concurrent callers observes RowsAffected > 0, so only one ever proceeds to
// issue/reject.
func (s *PostgresCMPTransactionStorage) ClaimPending(ctx context.Context, transactionID string) (models.CMPTransaction, bool, error) {
	switch s.db.Dialector.Name() {
	case "postgres", "mysql":
		var row cmpTransactionRow
		result := s.db.WithContext(ctx).
			Raw(
				`UPDATE cmp_transactions
				    SET state = ?
				  WHERE transaction_id = ? AND state = ? AND expires_at > `+nowExpr(s.db)+`
			  RETURNING *`,
				string(models.CMPTransactionStateApproving),
				transactionID,
				string(models.CMPTransactionStatePending),
			).
			Scan(&row)
		if result.Error != nil {
			s.logger.Errorf("cmp_transactions: claim-pending %s: %v", transactionID, result.Error)
			return models.CMPTransaction{}, false, result.Error
		}
		if result.RowsAffected == 0 {
			return models.CMPTransaction{}, false, nil
		}
		return rowToDomain(row), true, nil

	default:
		// SQLite serialises writes per-database file, so an explicit
		// transaction wrapping the read+update is equally race-free (same
		// rationale as Confirm's SQLite fallback).
		var out models.CMPTransaction
		var claimed bool
		txErr := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			var current cmpTransactionRow
			err := tx.Where("transaction_id = ? AND state = ? AND expires_at > "+nowExpr(s.db),
				transactionID, string(models.CMPTransactionStatePending)).
				First(&current).Error
			if err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return nil // claimed stays false
				}
				return err
			}
			if err := tx.Model(&current).Update("state", string(models.CMPTransactionStateApproving)).Error; err != nil {
				return err
			}
			current.State = string(models.CMPTransactionStateApproving)
			out = rowToDomain(current)
			claimed = true
			return nil
		})
		if txErr != nil {
			s.logger.Errorf("cmp_transactions: claim-pending %s: %v", transactionID, txErr)
			return models.CMPTransaction{}, false, txErr
		}
		return out, claimed, nil
	}
}

// WithDeviceLock runs fn while holding a Postgres transaction-scoped advisory
// lock (pg_advisory_xact_lock) keyed by hashtext(deviceID). The lock is
// acquired on whatever physical connection GORM's Transaction pins for the
// closure and is released automatically by Postgres at COMMIT/ROLLBACK, so
// there is no separate unlock call to forget. A second caller requesting the
// same deviceID blocks (does not fail) until the first's transaction ends —
// appropriate here because the callers of this method (see LWCEnroll) hold it
// only across a single bounded CA call, not an unbounded amount of work.
//
// On dialects with no advisory-lock primitive (SQLite, used for tests/dev), a
// process-local mutex keyed by deviceID is held instead. This used to run fn
// directly, on the reasoning that "a single writer already serializes access
// there" — but that is not what the callers need. SQLite serializes individual
// WRITES; it does not hold anything across the closure, and the closure's whole
// purpose is to make a read-decide-write sequence spanning a CA round trip
// atomic (see LWCEnroll's MaximumActiveCertificates check). Two goroutines in
// one process could therefore both read the count, both pass the check, and both
// issue — exactly the race the lock exists to close, silently reopened on every
// non-Postgres deployment.
//
// A process-local lock is sufficient there and nowhere else: these dialects are
// used only for single-process deployments. Postgres, which serves multi-replica
// deployments, keeps the cross-process advisory lock.
func (s *PostgresCMPTransactionStorage) WithDeviceLock(ctx context.Context, deviceID string, fn func(ctx context.Context) error) error {
	if s.db.Dialector.Name() != "postgres" {
		release := s.deviceLocks.acquire(deviceID)
		defer release()
		return fn(ctx)
	}
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("SELECT pg_advisory_xact_lock(hashtext(?))", deviceID).Error; err != nil {
			return fmt.Errorf("cmp: acquire device lock for %q: %w", deviceID, err)
		}
		return fn(ctx)
	})
}

// deviceLockTable is a set of mutexes keyed by device ID, used as the
// non-Postgres fallback for WithDeviceLock. Entries are reference-counted and
// dropped once idle so the table does not grow with every device ever seen.
//
// The zero value is ready to use.
type deviceLockTable struct {
	mu    sync.Mutex
	locks map[string]*deviceLockEntry
}

type deviceLockEntry struct {
	mu   sync.Mutex
	refs int
}

// acquire blocks until the lock for key is held, and returns the function that
// releases it.
func (t *deviceLockTable) acquire(key string) func() {
	t.mu.Lock()
	if t.locks == nil {
		t.locks = make(map[string]*deviceLockEntry)
	}
	entry, ok := t.locks[key]
	if !ok {
		entry = &deviceLockEntry{}
		t.locks[key] = entry
	}
	// Counted while the table lock is held, so the entry cannot be evicted
	// between here and the Lock below.
	entry.refs++
	t.mu.Unlock()

	entry.mu.Lock()

	return func() {
		entry.mu.Unlock()
		t.mu.Lock()
		entry.refs--
		if entry.refs == 0 {
			delete(t.locks, key)
		}
		t.mu.Unlock()
	}
}

// UpdateState transitions a transaction to a new state, atomically setting
// the certificate (when issuance succeeded) or ErrorMessage (when it failed),
// and re-bases ExpiresAt to the supplied deadline.
//
// The query is keyed solely by transaction_id — staleness is NOT filtered
// here because two distinct callers need to write past-expiry rows:
//   - the confirmation monitor transitions expired PENDING rows to
//     ISSUE_FAILED so they remain auditable;
//   - the admin approval path may race the monitor by a few ms across the
//     original expires_at boundary; rejecting in that window would orphan
//     a cert issued at the CA.
//
// Callers that need a staleness precondition MUST enforce it at the service
// layer before calling UpdateState (see ApproveCMPTransaction). Returns
// (true, nil) when a row was updated, (false, nil) when no row exists with
// the given transaction_id.
func (s *PostgresCMPTransactionStorage) UpdateState(ctx context.Context, transactionID string, state models.CMPTransactionState, cert *models.X509Certificate, errorMessage string, expiresAt time.Time) (bool, error) {
	updates := map[string]interface{}{
		"state":         string(state),
		"certificate":   certToString(cert),
		"error_message": errorMessage,
		"expires_at":    expiresAt,
	}
	if cert != nil {
		// Keep the denormalized lookup column in sync with the certificate being
		// stored (see cmpTransactionRow.CertSerialNumber). Without this, a
		// phased-approval transaction (ApproveCMPTransaction, the only caller
		// that moves a row from PENDING to ISSUED with a freshly issued cert)
		// leaves cert_serial_number at its PENDING-time empty value forever:
		// the in-memory struct returned to the approval caller looks correct,
		// but every later DB read (certConf, revocation-by-serial, the
		// confirmation monitor) sees "". A later LWCConfirmReenrollment lookup
		// with an empty serial hits the CA's list endpoint instead of a single
		// certificate and panics on the resulting nil certificate.
		updates["cert_serial_number"] = hex.EncodeToString((*x509.Certificate)(cert).SerialNumber.Bytes())
	}
	result := s.db.WithContext(ctx).
		Model(&cmpTransactionRow{}).
		Where("transaction_id = ?", transactionID).
		Updates(updates)
	if result.Error != nil {
		s.logger.Errorf("cmp_transactions: update-state %s → %s: %v", transactionID, state, result.Error)
		return false, result.Error
	}
	return result.RowsAffected > 0, nil
}

// SelectPending returns up to `limit` PENDING transactions whose ExpiresAt is
// still in the future, oldest first. Used by the async-issuance worker as its
// work-queue cursor. On Postgres the query uses SELECT FOR UPDATE SKIP LOCKED
// so multiple workers can claim disjoint rows in parallel without blocking
// each other; SQLite has no row-level locking and falls back to a plain SELECT
// (monolithic deployments run a single writer, so the contention is irrelevant).
func (s *PostgresCMPTransactionStorage) SelectPending(ctx context.Context, limit int) ([]models.CMPTransaction, error) {
	return s.selectLockedBatch(ctx, "select-pending",
		"state = ? AND expires_at > "+nowExpr(s.db), string(models.CMPTransactionStatePending),
		"created_at ASC", limit, 16)
}

// selectLockedBatch runs the shared "claim a batch of rows" query used by
// SelectPending, SelectExpiredPending and SelectExpiredIssued: default the
// limit when non-positive, filter by whereExpr/whereArg, order by orderExpr,
// and — on dialects that support it — take FOR UPDATE SKIP LOCKED so multiple
// workers/replicas claim disjoint rows. GORM's Dialector.Name() returns the
// short driver name ("postgres", "sqlite", "mysql", ...) so we whitelist
// explicitly rather than try/fall-back; SQLite has no row-level locking and
// falls back to a plain SELECT. logLabel names the operation in the error log.
func (s *PostgresCMPTransactionStorage) selectLockedBatch(ctx context.Context, logLabel, whereExpr string, whereArg any, orderExpr string, limit, defaultLimit int) ([]models.CMPTransaction, error) {
	if limit <= 0 {
		limit = defaultLimit
	}
	q := s.db.WithContext(ctx).
		Where(whereExpr, whereArg).
		Order(orderExpr).
		Limit(limit)

	switch s.db.Dialector.Name() {
	case "postgres", "mysql":
		q = q.Clauses(clause.Locking{Strength: "UPDATE", Options: "SKIP LOCKED"})
	}

	var rows []cmpTransactionRow
	if result := q.Find(&rows); result.Error != nil {
		s.logger.Errorf("cmp_transactions: %s: %v", logLabel, result.Error)
		return nil, result.Error
	}
	out := make([]models.CMPTransaction, len(rows))
	for i, r := range rows {
		out[i] = rowToDomain(r)
	}
	return out, nil
}

// DeleteExpired removes ISSUE_FAILED transactions whose expires_at is in the
// past. PENDING is intentionally NOT swept here — the confirmation monitor
// transitions expired PENDING rows to ISSUE_FAILED (with a fresh retention
// TTL) so the rejection is auditable and a later pollReq can surface the
// reason to the EE. ISSUED rows are NOT deleted either — they represent a
// cert that was actually issued at the CA, and the confirmation monitor
// revokes them. Terminal states (CONFIRMED, REVOKED) are never deleted by
// this method.
func (s *PostgresCMPTransactionStorage) DeleteExpired(ctx context.Context) error {
	result := s.db.WithContext(ctx).
		Where("expires_at < "+nowExpr(s.db)+" AND state = ?",
			string(models.CMPTransactionStateIssueFailed),
		).
		Delete(&cmpTransactionRow{})
	if result.Error != nil {
		s.logger.Errorf("cmp_transactions: delete-expired: %v", result.Error)
		return result.Error
	}
	if result.RowsAffected > 0 {
		s.logger.Debugf("cmp_transactions: deleted %d expired transaction(s)", result.RowsAffected)
	}
	return nil
}

// Confirm atomically transitions a transaction from ISSUED to CONFIRMED and
// returns the prior state in the same DB round-trip. The prior state lets the
// caller distinguish:
//
//   - prior == ISSUED, updated == true   → transition succeeded
//   - prior == REVOKED, updated == false → cert already revoked by the
//     confirmation monitor (race we must surface, not swallow)
//   - prior == CONFIRMED, updated == false → idempotent replay of a certConf
//   - prior == "" (zero), updated == false → row not found at all
//
// Implementation: a CTE captures the row state pre-update under FOR UPDATE so
// the read/update pair is atomic, then the UPDATE conditionally fires only
// when the state is still ISSUED. Both branches return one row to Scan.
func (s *PostgresCMPTransactionStorage) Confirm(ctx context.Context, transactionID string) (models.CMPTransaction, models.CMPTransactionState, bool, error) {
	type confirmRow struct {
		cmpTransactionRow
		PriorState string `gorm:"column:prior_state"`
		Updated    bool   `gorm:"column:updated"`
	}

	var row confirmRow

	switch s.db.Dialector.Name() {
	case "postgres", "mysql":
		// CTE-based atomic read+update. The locked SELECT pins the row so a
		// concurrent monitor-job revocation cannot slip between the prior-state
		// read and the conditional update.
		result := s.db.WithContext(ctx).
			Raw(
				`WITH prior AS (
				    SELECT state FROM cmp_transactions
				    WHERE transaction_id = ?
				    FOR UPDATE
				 ),
				 updated AS (
				    UPDATE cmp_transactions
				    SET state = ?, confirmed_at = `+nowExpr(s.db)+`
				    WHERE transaction_id = ? AND state = ?
				    RETURNING *
				 )
				 SELECT u.*,
				        p.state AS prior_state,
				        (u.transaction_id IS NOT NULL) AS updated
				   FROM prior p
				   LEFT JOIN updated u ON true`,
				transactionID,
				string(models.CMPTransactionStateConfirmed),
				transactionID,
				string(models.CMPTransactionStateIssued),
			).
			Scan(&row)

		if result.Error != nil {
			s.logger.Errorf("cmp_transactions: confirm %s: %v", transactionID, result.Error)
			return models.CMPTransaction{}, "", false, result.Error
		}
		if result.RowsAffected == 0 {
			// CTE returned nothing → row does not exist.
			return models.CMPTransaction{}, "", false, nil
		}
		prior := models.CMPTransactionState(row.PriorState)
		if !row.Updated {
			return models.CMPTransaction{}, prior, false, nil
		}
		return rowToDomain(row.cmpTransactionRow), prior, true, nil

	default:
		// SQLite (test / dev) has no CTE+UPDATE+RETURNING composition; we do the
		// read+update in an explicit transaction. SQLite serialises writes
		// per-database file so this is equally race-free for the single-process
		// use cases it covers.
		var prior models.CMPTransactionState
		var dataRow cmpTransactionRow
		var updated bool
		txErr := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			var current cmpTransactionRow
			err := tx.Where("transaction_id = ?", transactionID).First(&current).Error
			if err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return nil // prior stays ""; updated stays false
				}
				return err
			}
			prior = models.CMPTransactionState(current.State)
			if current.State != string(models.CMPTransactionStateIssued) {
				return nil
			}
			updates := map[string]interface{}{
				"state":        string(models.CMPTransactionStateConfirmed),
				"confirmed_at": time.Now(),
			}
			if err := tx.Model(&current).Updates(updates).Error; err != nil {
				return err
			}
			dataRow = current
			dataRow.State = string(models.CMPTransactionStateConfirmed)
			updated = true
			return nil
		})
		if txErr != nil {
			s.logger.Errorf("cmp_transactions: confirm %s: %v", transactionID, txErr)
			return models.CMPTransaction{}, "", false, txErr
		}
		if !updated {
			return models.CMPTransaction{}, prior, false, nil
		}
		return rowToDomain(dataRow), prior, true, nil
	}
}

// SelectExpiredPending returns up to `limit` PENDING transactions whose
// expires_at has already passed, oldest first. The CMP confirmation
// monitor uses this to find phased-workflow requests an administrator
// never acted on. Symmetric to SelectExpiredIssued: same SKIP LOCKED
// behaviour on Postgres/MySQL so two replicas don't double-process.
func (s *PostgresCMPTransactionStorage) SelectExpiredPending(ctx context.Context, limit int) ([]models.CMPTransaction, error) {
	// APPROVING rows are included alongside PENDING: APPROVING marks a row an
	// administrator started resolving (ClaimPending) but never finished —
	// normally a sub-second window, but a process crash between the claim
	// and the final ISSUED/ISSUE_FAILED write would otherwise strand the row
	// outside every sweep forever (its state is no longer PENDING). Folding
	// it into this same query means a stuck claim is recovered exactly like
	// an unresolved PENDING row once its ExpiresAt passes.
	return s.selectLockedBatch(ctx, "select-expired-pending",
		"state IN ? AND expires_at <= "+nowExpr(s.db),
		[]string{string(models.CMPTransactionStatePending), string(models.CMPTransactionStateApproving)},
		"expires_at ASC", limit, 100)
}

// SelectExpiredIssued returns up to `limit` ISSUED transactions whose
// expires_at has already passed, oldest first. These are enrollments that
// were issued at the CA but never confirmed by the EE within the DMS
// confirmation window. The confirmation monitor uses this to drive
// revocation: each cert is revoked at the CA and then the row itself is
// transitioned to REVOKED via MarkRevokedByTransactionID for audit.
func (s *PostgresCMPTransactionStorage) SelectExpiredIssued(ctx context.Context, limit int) ([]models.CMPTransaction, error) {
	// FOR UPDATE SKIP LOCKED ensures two backend replicas running the
	// confirmation monitor concurrently each pick a disjoint set of rows
	// rather than both racing to revoke the same certs at the CA
	// (audit finding S4). SelectPending uses the same pattern; the omission
	// here was the bug.
	//
	// REVOKING rows are included alongside ISSUED: REVOKING marks a row the
	// monitor started revoking (ClaimIssuedForRevocation) but never
	// finished — normally sub-second, but a process crash between the claim
	// and the final CA call/state write would otherwise strand the row
	// outside every sweep forever (its state is no longer ISSUED).
	return s.selectLockedBatch(ctx, "select-expired-issued",
		"state IN ? AND expires_at <= "+nowExpr(s.db),
		[]string{string(models.CMPTransactionStateIssued), string(models.CMPTransactionStateRevoking)},
		"expires_at ASC", limit, 100)
}

// ClaimIssuedForRevocation atomically transitions a transaction from ISSUED
// to REVOKING, conditioned on the row still being ISSUED, mirroring
// ClaimPending's conditional-update approach. Only one of ClaimIssuedForRevocation
// (this method) and Confirm (ISSUED → CONFIRMED) can ever observe
// RowsAffected > 0 for a given row, since both require state=ISSUED under the
// same row-level locking a plain UPDATE already provides — that is what
// closes the confirmation-monitor-vs-certConf race (see the interface doc).
func (s *PostgresCMPTransactionStorage) ClaimIssuedForRevocation(ctx context.Context, transactionID string) (models.CMPTransaction, bool, error) {
	switch s.db.Dialector.Name() {
	case "postgres", "mysql":
		var row cmpTransactionRow
		result := s.db.WithContext(ctx).
			Raw(
				`UPDATE cmp_transactions
				    SET state = ?
				  WHERE transaction_id = ? AND state = ?
			  RETURNING *`,
				string(models.CMPTransactionStateRevoking),
				transactionID,
				string(models.CMPTransactionStateIssued),
			).
			Scan(&row)
		if result.Error != nil {
			s.logger.Errorf("cmp_transactions: claim-issued-for-revocation %s: %v", transactionID, result.Error)
			return models.CMPTransaction{}, false, result.Error
		}
		if result.RowsAffected == 0 {
			return models.CMPTransaction{}, false, nil
		}
		return rowToDomain(row), true, nil

	default:
		var out models.CMPTransaction
		var claimed bool
		txErr := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			var current cmpTransactionRow
			err := tx.Where("transaction_id = ? AND state = ?",
				transactionID, string(models.CMPTransactionStateIssued)).
				First(&current).Error
			if err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return nil // claimed stays false
				}
				return err
			}
			if err := tx.Model(&current).Update("state", string(models.CMPTransactionStateRevoking)).Error; err != nil {
				return err
			}
			current.State = string(models.CMPTransactionStateRevoking)
			out = rowToDomain(current)
			claimed = true
			return nil
		})
		if txErr != nil {
			s.logger.Errorf("cmp_transactions: claim-issued-for-revocation %s: %v", transactionID, txErr)
			return models.CMPTransaction{}, false, txErr
		}
		return out, claimed, nil
	}
}

// MarkRevokedByTransactionID transitions the row identified by transactionID
// to REVOKED unconditionally — unlike MarkRevokedByCertSerial (which only
// touches CONFIRMED rows) and UpdateState (which only touches non-expired
// rows), this method targets expired ISSUED rows so the confirmation
// monitor can finalise them after revoking the cert at the CA.
func (s *PostgresCMPTransactionStorage) MarkRevokedByTransactionID(ctx context.Context, transactionID string) error {
	result := s.db.WithContext(ctx).
		Model(&cmpTransactionRow{}).
		Where("transaction_id = ?", transactionID).
		Update("state", string(models.CMPTransactionStateRevoked))
	if result.Error != nil {
		s.logger.Errorf("cmp_transactions: mark-revoked-by-tx %s: %v", transactionID, result.Error)
		return result.Error
	}
	return nil
}

// MarkRevokedByCertSerial transitions any CONFIRMED transaction with the given
// certificate serial number to REVOKED. No-op if no matching row exists.
func (s *PostgresCMPTransactionStorage) MarkRevokedByCertSerial(ctx context.Context, certSerialNumber string) error {
	result := s.db.WithContext(ctx).
		Model(&cmpTransactionRow{}).
		Where("cert_serial_number = ? AND state = ?", certSerialNumber, string(models.CMPTransactionStateConfirmed)).
		Update("state", string(models.CMPTransactionStateRevoked))
	if result.Error != nil {
		s.logger.Errorf("cmp_transactions: mark-revoked serial=%s: %v", certSerialNumber, result.Error)
		return result.Error
	}
	if result.RowsAffected > 0 {
		s.logger.Infof("cmp_transactions: marked %d transaction(s) as REVOKED for serial %s", result.RowsAffected, certSerialNumber)
	}
	return nil
}

// SelectAllByDMS streams every transaction belonging to the given DMS,
// applying the standard pagination/sort/filter machinery. Unlike the
// protocol-facing methods this one deliberately does NOT filter on
// expires_at — operators need to see stale rows to debug enrollment
// failures, and DeleteExpired is expected to be infrequent on dev/test
// systems where this listing is most useful.
func (s *PostgresCMPTransactionStorage) SelectAllByDMS(
	ctx context.Context,
	dmsID string,
	exhaustiveRun bool,
	applyFunc func(models.CMPTransaction),
	queryParams *resources.QueryParameters,
) (string, error) {
	extra := []GormExtraOps{{
		Query:           "dms_id = ?",
		AdditionalWhere: []interface{}{dmsID},
	}}
	return s.querier.SelectAll(ctx, queryParams, extra, exhaustiveRun, func(row cmpTransactionRow) {
		applyFunc(rowToDomain(row))
	})
}

func rowToDomain(row cmpTransactionRow) models.CMPTransaction {
	return models.CMPTransaction{
		TransactionID:               row.TransactionID,
		DMSID:                       row.DMSID,
		CertSerialNumber:            row.CertSerialNumber,
		Certificate:                 stringToCert(row.Certificate),
		SentNonce:                   row.SentNonce,
		ReceivedNonce:               row.ReceivedNonce,
		SupersededCertSerial:        row.SupersededCertSerial,
		RegToken:                    row.RegToken,
		PopoChallenge:               row.PopoChallenge,
		State:                       models.CMPTransactionState(row.State),
		ErrorMessage:                row.ErrorMessage,
		CSR:                         stringToCSR(row.CSR),
		IsReenrollment:              row.IsReenrollment,
		CentralKeyGeneration:        row.CentralKeyGeneration,
		RequestType:                 row.RequestType,
		POPOMethod:                  row.POPOMethod,
		ChallengeType:               row.ChallengeType,
		AuthenticatorControlPresent: row.AuthenticatorControlPresent,
		AuthModeAtEnrollment:        row.AuthModeAtEnrollment,
		SubjectCommonName:           row.SubjectCommonName,
		WFXJobID:                    row.WFXJobID,
		ConfirmedAt:                 row.ConfirmedAt,
		ExpiresAt:                   row.ExpiresAt,
		CreatedAt:                   row.CreatedAt,
	}
}
