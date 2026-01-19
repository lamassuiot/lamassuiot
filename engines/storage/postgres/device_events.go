package postgres

import (
	"context"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type PostgresDeviceEventsStore struct {
	db      *gorm.DB
	querier *postgresDBQuerier[models.DeviceEvent]
}

func NewDeviceEventsRepository(logger *logrus.Entry, db *gorm.DB) (storage.DeviceEventsRepo, error) {
	querier, err := TableQuery(logger, db, "device_events", []string{"timestamp", "device_id"}, models.DeviceEvent{})
	if err != nil {
		return nil, err
	}

	return &PostgresDeviceEventsStore{
		db:      db,
		querier: querier,
	}, nil
}

func (db *PostgresDeviceEventsStore) Select(ctx context.Context, deviceID string, exhaustiveRun bool, applyFunc func(models.DeviceEvent), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error) {
	opts := []gormExtraOps{
		{query: "device_id = ?", additionalWhere: []any{deviceID}},
	}
	return db.querier.SelectAll(ctx, queryParams, opts, exhaustiveRun, applyFunc)
}

func (db *PostgresDeviceEventsStore) Insert(ctx context.Context, device *models.DeviceEvent) (*models.DeviceEvent, error) {
	return db.querier.Insert(ctx, device)
}
