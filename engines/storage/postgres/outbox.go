package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var ErrEventOutboxRecordConflict = errors.New("event outbox record conflicts with an existing event ID")

type EventOutboxStore struct {
	db *gorm.DB
}

// WithTenantOutboxTransaction commits a domain mutation and its event record atomically.
func WithTenantOutboxTransaction(ctx context.Context, db *gorm.DB, record *models.EventOutboxRecord, mutate func(*gorm.DB) error) error {
	if mutate == nil {
		return errors.New("event outbox mutation is required")
	}
	if record == nil || record.EventID == "" || record.TenantID == "" || record.OrganizationID == "" || record.CorrelationID == "" || record.Type == "" || record.Version == "" || len(record.Payload) == 0 {
		return errors.New("event outbox record identifiers and payload are required")
	}
	tenantContext, err := core.RequireTenantContext(ctx)
	if err != nil {
		return fmt.Errorf("create tenant outbox transaction: %w", err)
	}
	if tenantContext.TenantID != record.TenantID || tenantContext.OrganizationID != record.OrganizationID {
		return fmt.Errorf("create tenant outbox transaction: %w", ErrEventOutboxRecordConflict)
	}
	if record.Status == "" {
		record.Status = models.EventOutboxPending
	}
	if record.AvailableAt.IsZero() {
		record.AvailableAt = time.Now().UTC()
	}
	if record.CreatedAt.IsZero() {
		record.CreatedAt = time.Now().UTC()
	}

	return WithTenantTransaction(ctx, db, func(tx *gorm.DB) error {
		if err := mutate(tx); err != nil {
			return err
		}
		return tx.Create(record).Error
	})
}

func NewEventOutboxRepository(db *gorm.DB) *EventOutboxStore {
	return &EventOutboxStore{db: db}
}

func (store *EventOutboxStore) Enqueue(ctx context.Context, record *models.EventOutboxRecord) error {
	if record == nil || record.EventID == "" || record.TenantID == "" || record.OrganizationID == "" || record.CorrelationID == "" || record.Type == "" || record.Version == "" || len(record.Payload) == 0 {
		return errors.New("event outbox record identifiers and payload are required")
	}
	tenantContext, err := core.RequireTenantContext(ctx)
	if err != nil {
		return fmt.Errorf("enqueue event outbox: %w", err)
	}
	if tenantContext.TenantID != record.TenantID || tenantContext.OrganizationID != record.OrganizationID {
		return fmt.Errorf("enqueue event outbox: %w", ErrEventOutboxRecordConflict)
	}
	if record.Status == "" {
		record.Status = models.EventOutboxPending
	}
	if record.AvailableAt.IsZero() {
		record.AvailableAt = time.Now().UTC()
	}
	if record.CreatedAt.IsZero() {
		record.CreatedAt = time.Now().UTC()
	}

	err = WithTenantTransaction(ctx, store.db, func(tx *gorm.DB) error {
		return tx.Create(record).Error
	})
	if err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return fmt.Errorf("enqueue event outbox: %w", ErrEventOutboxRecordConflict)
		}
		return fmt.Errorf("enqueue event outbox: %w", err)
	}
	return nil
}

func (store *EventOutboxStore) ClaimPending(ctx context.Context, limit int) ([]models.EventOutboxRecord, error) {
	if limit <= 0 {
		return nil, errors.New("event outbox claim limit must be positive")
	}
	tenantContext, err := core.RequireTenantContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("claim event outbox: %w", err)
	}
	var records []models.EventOutboxRecord
	err = WithTenantTransaction(ctx, store.db, func(tx *gorm.DB) error {
		if err := tx.Where("tenant_id = ? AND status = ? AND available_at <= ?", tenantContext.TenantID, models.EventOutboxPending, time.Now().UTC()).
			Order("created_at ASC").Limit(limit).Clauses(clause.Locking{Strength: "UPDATE", Options: "SKIP LOCKED"}).Find(&records).Error; err != nil {
			return err
		}
		if len(records) == 0 {
			return nil
		}
		ids := make([]string, 0, len(records))
		for index := range records {
			records[index].Attempts++
			ids = append(ids, records[index].EventID)
		}
		return tx.Model(&models.EventOutboxRecord{}).Where("tenant_id = ? AND event_id IN ?", tenantContext.TenantID, ids).
			Updates(map[string]interface{}{"attempts": gorm.Expr("attempts + 1")}).Error
	})
	if err != nil {
		return nil, fmt.Errorf("claim event outbox: %w", err)
	}
	return records, nil
}

func (store *EventOutboxStore) MarkPublished(ctx context.Context, eventID string) error {
	return store.updateStatus(ctx, eventID, models.EventOutboxPublished, "")
}

func (store *EventOutboxStore) ScheduleRetry(ctx context.Context, eventID string, reason string, availableAt time.Time) error {
	if reason == "" || availableAt.IsZero() {
		return errors.New("event outbox retry reason and availability are required")
	}
	tenantContext, err := core.RequireTenantContext(ctx)
	if err != nil {
		return fmt.Errorf("schedule event outbox retry: %w", err)
	}
	updates := map[string]interface{}{
		"status":       models.EventOutboxPending,
		"available_at": availableAt,
		"last_error":   reason,
	}
	if err := store.updateTenantRecord(ctx, tenantContext.TenantID, eventID, updates); err != nil {
		return fmt.Errorf("schedule event outbox retry: %w", err)
	}
	return nil
}

func (store *EventOutboxStore) MarkFailed(ctx context.Context, eventID string, reason string) error {
	if reason == "" {
		return errors.New("event outbox failure reason is required")
	}
	return store.updateStatus(ctx, eventID, models.EventOutboxFailed, reason)
}

func (store *EventOutboxStore) updateStatus(ctx context.Context, eventID string, status models.EventOutboxStatus, reason string) error {
	if eventID == "" {
		return errors.New("event outbox event ID is required")
	}
	tenantContext, err := core.RequireTenantContext(ctx)
	if err != nil {
		return fmt.Errorf("update event outbox: %w", err)
	}
	updates := map[string]interface{}{"status": status}
	if status == models.EventOutboxPublished {
		now := time.Now().UTC()
		updates["published_at"] = &now
	}
	if reason != "" {
		updates["last_error"] = reason
	}
	if err := store.updateTenantRecord(ctx, tenantContext.TenantID, eventID, updates); err != nil {
		return fmt.Errorf("update event outbox: %w", err)
	}
	return nil
}

// updateTenantRecord actualiza un evento dentro de una transacción con el tenant
// fijado, para que la política RLS de event_outbox lo permita.
func (store *EventOutboxStore) updateTenantRecord(ctx context.Context, tenantID, eventID string, updates map[string]interface{}) error {
	return WithTenantTransaction(ctx, store.db, func(tx *gorm.DB) error {
		result := tx.Model(&models.EventOutboxRecord{}).
			Where("tenant_id = ? AND event_id = ?", tenantID, eventID).
			Updates(updates)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return gorm.ErrRecordNotFound
		}
		return nil
	})
}
