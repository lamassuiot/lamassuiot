package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type eventRetentionSettingsRow struct {
	ID            int       `gorm:"primaryKey;column:id"`
	AuditEventTTL string    `gorm:"column:audit_event_ttl"`
	UpdatedAt     time.Time `gorm:"column:updated_at"`
}

func (eventRetentionSettingsRow) TableName() string {
	return "event_retention_settings"
}

type PostgresEventRetentionSettingsStore struct {
	db *gorm.DB
}

func NewEventRetentionSettingsPostgresRepository(logger *logrus.Entry, db *gorm.DB) (storage.EventRetentionSettingsRepository, error) {
	return &PostgresEventRetentionSettingsStore{db: db}, nil
}

func (s *PostgresEventRetentionSettingsStore) Get(ctx context.Context) (*models.EventRetentionSettings, error) {
	var row eventRetentionSettingsRow
	if err := s.db.WithContext(ctx).First(&row, 1).Error; err != nil {
		return nil, fmt.Errorf("could not read event retention settings: %w", err)
	}

	auditTTL, err := models.ParseDuration(row.AuditEventTTL)
	if err != nil {
		return nil, fmt.Errorf("invalid audit_event_ttl %q: %w", row.AuditEventTTL, err)
	}

	return &models.EventRetentionSettings{
		AuditEventTTL: models.TimeDuration(auditTTL),
		UpdatedAt:     row.UpdatedAt,
	}, nil
}

func (s *PostgresEventRetentionSettingsStore) Update(ctx context.Context, settings *models.EventRetentionSettings) (*models.EventRetentionSettings, error) {
	now := time.Now()
	row := eventRetentionSettingsRow{
		ID:            1,
		AuditEventTTL: settings.AuditEventTTL.String(),
		UpdatedAt:     now,
	}

	result := s.db.WithContext(ctx).
		Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "id"}},
			DoUpdates: clause.AssignmentColumns([]string{"audit_event_ttl", "updated_at"}),
		}).
		Create(&row)

	if result.Error != nil {
		return nil, fmt.Errorf("could not update event retention settings: %w", result.Error)
	}

	settings.UpdatedAt = now
	return settings, nil
}
