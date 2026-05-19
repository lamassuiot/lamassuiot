package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// cmpTransactionRow is the GORM model that maps to the cmp_transactions table.
// It is intentionally kept private; callers use the domain type storage.CMPTransaction.
type cmpTransactionRow struct {
	TransactionID  string    `gorm:"primaryKey;column:transaction_id"`
	DMSID          string    `gorm:"column:dms_id;not null"`
	CertDER        []byte    `gorm:"column:cert_der"`
	SentNonce      []byte    `gorm:"column:sent_nonce;not null"`
	State          string    `gorm:"column:state;not null;default:ISSUED"`
	ErrorMessage   string    `gorm:"column:error_message;not null;default:''"`
	CSRDER         []byte    `gorm:"column:csr_der"`
	IsReenrollment bool      `gorm:"column:is_reenrollment;not null;default:false"`
	ExpiresAt      time.Time `gorm:"column:expires_at;not null"`
	CreatedAt      time.Time `gorm:"column:created_at;autoCreateTime"`
}

func (cmpTransactionRow) TableName() string { return "cmp_transactions" }

// PostgresCMPTransactionStorage implements storage.CMPTransactionRepo using Postgres.
type PostgresCMPTransactionStorage struct {
	db     *gorm.DB
	logger *logrus.Entry
}

// NewCMPTransactionRepository creates a PostgresCMPTransactionStorage backed by
// the provided *gorm.DB. The caller is responsible for ensuring the
// cmp_transactions table exists (via the goose migration).
func NewCMPTransactionRepository(logger *logrus.Entry, db *gorm.DB) (storage.CMPTransactionRepo, error) {
	return &PostgresCMPTransactionStorage{db: db, logger: logger}, nil
}

// Exists reports whether a non-expired transaction with the given hex
// transactionID is present. It is a lightweight read-only check so the CMP
// controller can reject replayed requests before triggering any enrollment
// side-effects.
func (s *PostgresCMPTransactionStorage) Exists(ctx context.Context, transactionID string) (bool, error) {
	var count int64
	result := s.db.WithContext(ctx).
		Model(&cmpTransactionRow{}).
		Where("transaction_id = ? AND expires_at > ?", transactionID, time.Now()).
		Count(&count)
	if result.Error != nil {
		s.logger.Errorf("cmp_transactions: exists %s: %v", transactionID, result.Error)
		return false, result.Error
	}
	return count > 0, nil
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
		TransactionID:  tx.TransactionID,
		DMSID:          tx.DMSID,
		CertDER:        tx.CertDER,
		SentNonce:      tx.SentNonce,
		State:          string(state),
		ErrorMessage:   tx.ErrorMessage,
		CSRDER:         tx.CSRDER,
		IsReenrollment: tx.IsReenrollment,
		ExpiresAt:      tx.ExpiresAt,
		CreatedAt:      tx.CreatedAt,
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

// Select reads a non-expired transaction by ID without modifying it. Used by
// pollReq, which is allowed to be called multiple times against the same row.
func (s *PostgresCMPTransactionStorage) Select(ctx context.Context, transactionID string) (storage.CMPTransaction, bool, error) {
	var row cmpTransactionRow
	result := s.db.WithContext(ctx).
		Where("transaction_id = ? AND expires_at > ?", transactionID, time.Now()).
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
			  WHERE transaction_id = ? AND expires_at > ?
			  RETURNING *`,
			transactionID, time.Now(),
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
// CertDER (when issuing succeeded) or ErrorMessage (when it failed). A row
// that has already expired or been deleted by another worker is silently
// ignored — the caller sees nil error and treats the operation as a no-op.
func (s *PostgresCMPTransactionStorage) UpdateState(ctx context.Context, transactionID string, state storage.CMPTransactionState, certDER []byte, errorMessage string) error {
	updates := map[string]interface{}{
		"state":         string(state),
		"cert_der":      certDER,
		"error_message": errorMessage,
	}
	result := s.db.WithContext(ctx).
		Model(&cmpTransactionRow{}).
		Where("transaction_id = ? AND expires_at > ?", transactionID, time.Now()).
		Updates(updates)
	if result.Error != nil {
		s.logger.Errorf("cmp_transactions: update-state %s → %s: %v", transactionID, state, result.Error)
		return result.Error
	}
	return nil
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
		Where("state = ? AND expires_at > ?", string(storage.CMPTransactionStatePending), time.Now()).
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

// DeleteExpired removes all rows whose expires_at is strictly before now().
// A single DELETE with the indexed expires_at column is efficient even for
// large tables; the index on expires_at makes this O(expired rows), not O(all rows).
func (s *PostgresCMPTransactionStorage) DeleteExpired(ctx context.Context) error {
	result := s.db.WithContext(ctx).
		Where("expires_at < ?", time.Now()).
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

func rowToDomain(row cmpTransactionRow) storage.CMPTransaction {
	return storage.CMPTransaction{
		TransactionID:  row.TransactionID,
		DMSID:          row.DMSID,
		CertDER:        row.CertDER,
		SentNonce:      row.SentNonce,
		State:          storage.CMPTransactionState(row.State),
		ErrorMessage:   row.ErrorMessage,
		CSRDER:         row.CSRDER,
		IsReenrollment: row.IsReenrollment,
		ExpiresAt:      row.ExpiresAt,
		CreatedAt:      row.CreatedAt,
	}
}
