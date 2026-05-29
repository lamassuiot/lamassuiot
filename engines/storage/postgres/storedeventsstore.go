package postgres

import (
	"context"
	"time"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type PostgresStoredEventsStore struct {
	db      *gorm.DB
	querier *postgresDBQuerier[models.StoredEvent]
}

func NewStoredEventsPostgresRepository(logger *logrus.Entry, db *gorm.DB) (storage.StoredEventsRepository, error) {
	querier, err := TableQuery(logger, db, "stored_events", "id", models.StoredEvent{})
	if err != nil {
		return nil, err
	}

	return &PostgresStoredEventsStore{
		db:      db,
		querier: (*postgresDBQuerier[models.StoredEvent])(querier),
	}, nil
}

func (s *PostgresStoredEventsStore) Insert(ctx context.Context, ev *models.StoredEvent) (*models.StoredEvent, error) {
	return s.querier.Insert(ctx, ev, ev.ID)
}

func (s *PostgresStoredEventsStore) GetByID(ctx context.Context, id string) (bool, *models.StoredEvent, error) {
	return s.querier.SelectExists(ctx, id, nil)
}

func (s *PostgresStoredEventsStore) GetAll(ctx context.Context, exhaustiveRun bool, applyFunc func(models.StoredEvent), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error) {
	return s.querier.SelectAll(ctx, queryParams, []gormExtraOps{}, exhaustiveRun, applyFunc)
}

func (s *PostgresStoredEventsStore) DeleteExpired(ctx context.Context) (int64, error) {
	result := s.db.WithContext(ctx).
		Table("stored_events").
		Where("expires_at < ?", time.Now()).
		Delete(nil)
	return result.RowsAffected, result.Error
}
