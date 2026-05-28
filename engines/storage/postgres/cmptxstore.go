package postgres

import (
	"context"
	"errors"
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
// It is intentionally kept private; callers use the domain type storage.CMPTransaction.
type cmpTransactionRow struct {
	TransactionID     string    `gorm:"primaryKey;column:transaction_id"`
	DMSID             string    `gorm:"column:dms_id;not null"`
	CertSerialNumber  string    `gorm:"column:cert_serial_number;not null;default:''"`
	Certificate       string    `gorm:"column:certificate"`                    // base64-PEM text; empty for PENDING rows
	SentNonce         string    `gorm:"column:sent_nonce;not null;default:''"` // hex-encoded bytes
	State             string    `gorm:"column:state;not null;default:ISSUED"`
	ErrorMessage      string    `gorm:"column:error_message;not null;default:''"`
	CSR               string    `gorm:"column:csr"` // base64-PEM text; empty for ISSUED rows
	IsReenrollment    bool      `gorm:"column:is_reenrollment;not null;default:false"`
	RequestType       string    `gorm:"column:request_type;not null;default:''"`
	SubjectCommonName string    `gorm:"column:subject_common_name;not null;default:''"`
	WFXJobID          string    `gorm:"column:wfx_job_id;not null;default:''"`
	ConfirmedAt       time.Time `gorm:"column:confirmed_at"`
	ExpiresAt         time.Time `gorm:"column:expires_at;not null"`
	CreatedAt         time.Time `gorm:"column:created_at;autoCreateTime"`
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

// PostgresCMPTransactionStorage implements storage.CMPTransactionRepo using Postgres.
type PostgresCMPTransactionStorage struct {
	db      *gorm.DB
	logger  *logrus.Entry
	querier *postgresDBQuerier[cmpTransactionRow]
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
			string(storage.CMPTransactionStatePending),
			string(storage.CMPTransactionStateIssued),
		).
		Count(&count)
	if result.Error != nil {
		s.logger.Errorf("cmp_transactions: exists %s: %v", transactionID, result.Error)
		return false, result.Error
	}
	return count > 0, nil
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
// ISSUED with CertDER populated; async issuance sets PENDING with CSRDER + the
// IsReenrollment flag so the worker can later finish issuance.
func (s *PostgresCMPTransactionStorage) Insert(ctx context.Context, tx storage.CMPTransaction) error {
	state := tx.State
	if state == "" {
		// Backward-compatible default for callers that didn't yet set State.
		state = storage.CMPTransactionStateIssued
	}
	row := cmpTransactionRow{
		TransactionID:     tx.TransactionID,
		DMSID:             tx.DMSID,
		CertSerialNumber:  tx.CertSerialNumber,
		Certificate:       certToString(tx.Certificate),
		SentNonce:         tx.SentNonce,
		State:             string(state),
		ErrorMessage:      tx.ErrorMessage,
		CSR:               csrToString(tx.CSR),
		IsReenrollment:    tx.IsReenrollment,
		RequestType:       tx.RequestType,
		SubjectCommonName: tx.SubjectCommonName,
		WFXJobID:          tx.WFXJobID,
		ConfirmedAt:       tx.ConfirmedAt,
		ExpiresAt:         tx.ExpiresAt,
		CreatedAt:         tx.CreatedAt,
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
func (s *PostgresCMPTransactionStorage) Select(ctx context.Context, transactionID string) (storage.CMPTransaction, bool, error) {
	var row cmpTransactionRow
	result := s.db.WithContext(ctx).
		Where("transaction_id = ? AND (state IN (?,?,?) OR expires_at > "+nowExpr(s.db)+")",
			transactionID,
			string(storage.CMPTransactionStateConfirmed),
			string(storage.CMPTransactionStateRevoked),
			string(storage.CMPTransactionStateIssueFailed),
		).
		First(&row)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return storage.CMPTransaction{}, false, nil
		}
		s.logger.Errorf("cmp_transactions: select %s: %v", transactionID, result.Error)
		return storage.CMPTransaction{}, false, result.Error
	}
	return rowToDomain(row), true, nil
}

// SelectIncludingExpired reads a transaction by ID with NO state or expiry
// filtering. Used by error-reporting paths that need to tell apart "row never
// existed" from "row past ExpiresAt but not yet swept by the monitor". Callers
// must not act on the returned row's contents for issuance decisions — Select
// is the right method for those.
func (s *PostgresCMPTransactionStorage) SelectIncludingExpired(ctx context.Context, transactionID string) (storage.CMPTransaction, bool, error) {
	var row cmpTransactionRow
	result := s.db.WithContext(ctx).
		Where("transaction_id = ?", transactionID).
		First(&row)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return storage.CMPTransaction{}, false, nil
		}
		s.logger.Errorf("cmp_transactions: select-any %s: %v", transactionID, result.Error)
		return storage.CMPTransaction{}, false, result.Error
	}
	return rowToDomain(row), true, nil
}

// SelectAndDelete atomically fetches and deletes a transaction by its hex
// transactionID. Using DELETE ... RETURNING * is a single round-trip and fully
// atomic under Postgres's default READ COMMITTED isolation — no separate SELECT
// is needed, preventing TOCTOU races across concurrent server replicas.
//
// Expired rows are treated as non-existent: the caller sees (zero, false, nil).
func (s *PostgresCMPTransactionStorage) SelectAndDelete(ctx context.Context, transactionID string) (storage.CMPTransaction, bool, error) {
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
			return storage.CMPTransaction{}, false, nil
		}
		s.logger.Errorf("cmp_transactions: select-and-delete %s: %v", transactionID, result.Error)
		return storage.CMPTransaction{}, false, result.Error
	}
	if result.RowsAffected == 0 {
		return storage.CMPTransaction{}, false, nil
	}

	return rowToDomain(row), true, nil
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
func (s *PostgresCMPTransactionStorage) UpdateState(ctx context.Context, transactionID string, state storage.CMPTransactionState, cert *models.X509Certificate, errorMessage string, expiresAt time.Time) (bool, error) {
	updates := map[string]interface{}{
		"state":         string(state),
		"certificate":   certToString(cert),
		"error_message": errorMessage,
		"expires_at":    expiresAt,
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
func (s *PostgresCMPTransactionStorage) SelectPending(ctx context.Context, limit int) ([]storage.CMPTransaction, error) {
	if limit <= 0 {
		limit = 16
	}
	q := s.db.WithContext(ctx).
		Where("state = ? AND expires_at > "+nowExpr(s.db), string(storage.CMPTransactionStatePending)).
		Order("created_at ASC").
		Limit(limit)

	// Apply row-level locking only on dialects that support it. GORM's
	// Dialector.Name() returns the short driver name ("postgres", "sqlite",
	// "mysql", ...) so we whitelist explicitly rather than try/fall-back.
	switch s.db.Dialector.Name() {
	case "postgres", "mysql":
		q = q.Clauses(clause.Locking{Strength: "UPDATE", Options: "SKIP LOCKED"})
	}

	var rows []cmpTransactionRow
	if result := q.Find(&rows); result.Error != nil {
		s.logger.Errorf("cmp_transactions: select-pending: %v", result.Error)
		return nil, result.Error
	}
	out := make([]storage.CMPTransaction, len(rows))
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
			string(storage.CMPTransactionStateIssueFailed),
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
func (s *PostgresCMPTransactionStorage) Confirm(ctx context.Context, transactionID string) (storage.CMPTransaction, storage.CMPTransactionState, bool, error) {
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
				string(storage.CMPTransactionStateConfirmed),
				transactionID,
				string(storage.CMPTransactionStateIssued),
			).
			Scan(&row)

		if result.Error != nil {
			s.logger.Errorf("cmp_transactions: confirm %s: %v", transactionID, result.Error)
			return storage.CMPTransaction{}, "", false, result.Error
		}
		if result.RowsAffected == 0 {
			// CTE returned nothing → row does not exist.
			return storage.CMPTransaction{}, "", false, nil
		}
		prior := storage.CMPTransactionState(row.PriorState)
		if !row.Updated {
			return storage.CMPTransaction{}, prior, false, nil
		}
		return rowToDomain(row.cmpTransactionRow), prior, true, nil

	default:
		// SQLite (test / dev) has no CTE+UPDATE+RETURNING composition; we do the
		// read+update in an explicit transaction. SQLite serialises writes
		// per-database file so this is equally race-free for the single-process
		// use cases it covers.
		var prior storage.CMPTransactionState
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
			prior = storage.CMPTransactionState(current.State)
			if current.State != string(storage.CMPTransactionStateIssued) {
				return nil
			}
			updates := map[string]interface{}{
				"state":        string(storage.CMPTransactionStateConfirmed),
				"confirmed_at": time.Now(),
			}
			if err := tx.Model(&current).Updates(updates).Error; err != nil {
				return err
			}
			dataRow = current
			dataRow.State = string(storage.CMPTransactionStateConfirmed)
			updated = true
			return nil
		})
		if txErr != nil {
			s.logger.Errorf("cmp_transactions: confirm %s: %v", transactionID, txErr)
			return storage.CMPTransaction{}, "", false, txErr
		}
		if !updated {
			return storage.CMPTransaction{}, prior, false, nil
		}
		return rowToDomain(dataRow), prior, true, nil
	}
}

// SelectExpiredPending returns up to `limit` PENDING transactions whose
// expires_at has already passed, oldest first. The CMP confirmation
// monitor uses this to find phased-workflow requests an administrator
// never acted on. Symmetric to SelectExpiredIssued: same SKIP LOCKED
// behaviour on Postgres/MySQL so two replicas don't double-process.
func (s *PostgresCMPTransactionStorage) SelectExpiredPending(ctx context.Context, limit int) ([]storage.CMPTransaction, error) {
	if limit <= 0 {
		limit = 100
	}
	q := s.db.WithContext(ctx).
		Where("state = ? AND expires_at <= "+nowExpr(s.db), string(storage.CMPTransactionStatePending)).
		Order("expires_at ASC").
		Limit(limit)

	switch s.db.Dialector.Name() {
	case "postgres", "mysql":
		q = q.Clauses(clause.Locking{Strength: "UPDATE", Options: "SKIP LOCKED"})
	}

	var rows []cmpTransactionRow
	if result := q.Find(&rows); result.Error != nil {
		s.logger.Errorf("cmp_transactions: select-expired-pending: %v", result.Error)
		return nil, result.Error
	}
	out := make([]storage.CMPTransaction, len(rows))
	for i, r := range rows {
		out[i] = rowToDomain(r)
	}
	return out, nil
}

// SelectExpiredIssued returns up to `limit` ISSUED transactions whose
// expires_at has already passed, oldest first. These are enrollments that
// were issued at the CA but never confirmed by the EE within the DMS
// confirmation window. The confirmation monitor uses this to drive
// revocation: each cert is revoked at the CA and then the row itself is
// transitioned to REVOKED via MarkRevokedByTransactionID for audit.
func (s *PostgresCMPTransactionStorage) SelectExpiredIssued(ctx context.Context, limit int) ([]storage.CMPTransaction, error) {
	if limit <= 0 {
		limit = 100
	}
	q := s.db.WithContext(ctx).
		Where("state = ? AND expires_at <= "+nowExpr(s.db), string(storage.CMPTransactionStateIssued)).
		Order("expires_at ASC").
		Limit(limit)

	// FOR UPDATE SKIP LOCKED ensures two backend replicas running the
	// confirmation monitor concurrently each pick a disjoint set of rows
	// rather than both racing to revoke the same certs at the CA
	// (audit finding S4). SelectPending uses the same pattern; the omission
	// here was the bug.
	switch s.db.Dialector.Name() {
	case "postgres", "mysql":
		q = q.Clauses(clause.Locking{Strength: "UPDATE", Options: "SKIP LOCKED"})
	}

	var rows []cmpTransactionRow
	if result := q.Find(&rows); result.Error != nil {
		s.logger.Errorf("cmp_transactions: select-expired-issued: %v", result.Error)
		return nil, result.Error
	}
	out := make([]storage.CMPTransaction, len(rows))
	for i, r := range rows {
		out[i] = rowToDomain(r)
	}
	return out, nil
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
		Update("state", string(storage.CMPTransactionStateRevoked))
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
		Where("cert_serial_number = ? AND state = ?", certSerialNumber, string(storage.CMPTransactionStateConfirmed)).
		Update("state", string(storage.CMPTransactionStateRevoked))
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
	applyFunc func(storage.CMPTransaction),
	queryParams *resources.QueryParameters,
) (string, error) {
	extra := []gormExtraOps{{
		query:           "dms_id = ?",
		additionalWhere: []interface{}{dmsID},
	}}
	return s.querier.SelectAll(ctx, queryParams, extra, exhaustiveRun, func(row cmpTransactionRow) {
		applyFunc(rowToDomain(row))
	})
}

func rowToDomain(row cmpTransactionRow) storage.CMPTransaction {
	return storage.CMPTransaction{
		TransactionID:     row.TransactionID,
		DMSID:             row.DMSID,
		CertSerialNumber:  row.CertSerialNumber,
		Certificate:       stringToCert(row.Certificate),
		SentNonce:         row.SentNonce,
		State:             storage.CMPTransactionState(row.State),
		ErrorMessage:      row.ErrorMessage,
		CSR:               stringToCSR(row.CSR),
		IsReenrollment:    row.IsReenrollment,
		RequestType:       row.RequestType,
		SubjectCommonName: row.SubjectCommonName,
		WFXJobID:          row.WFXJobID,
		ConfirmedAt:       row.ConfirmedAt,
		ExpiresAt:         row.ExpiresAt,
		CreatedAt:         row.CreatedAt,
	}
}
