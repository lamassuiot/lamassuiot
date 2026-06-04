package postgres

import (
	"context"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type PostgresDeviceEventsStore struct {
	db      *gorm.DB
	querier *postgresDBQuerier[models.DeviceEventRecord]
}

func NewDeviceEventsRepository(logger *logrus.Entry, db *gorm.DB) (storage.DeviceEventsRepo, error) {
	querier, err := TableQuery(logger, db, "device_events", "id", models.DeviceEventRecord{})
	if err != nil {
		return nil, err
	}

	return &PostgresDeviceEventsStore{
		db:      db,
		querier: querier,
	}, nil
}

func (db *PostgresDeviceEventsStore) Insert(ctx context.Context, event *models.DeviceEventRecord) (*models.DeviceEventRecord, error) {
	return db.querier.Insert(ctx, event, event.ID)
}

func (db *PostgresDeviceEventsStore) SelectByDeviceID(ctx context.Context, req storage.StorageListRequest[models.DeviceEventRecord], deviceID string) (string, error) {
	opts := []gormExtraOps{
		{query: "device_id = ?", additionalWhere: []any{deviceID}},
	}

	return db.querier.SelectAll(ctx, req.QueryParams, opts, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *PostgresDeviceEventsStore) DeleteByDeviceID(ctx context.Context, deviceID string) error {
	return db.db.WithContext(ctx).Where("device_id = ?", deviceID).Delete(&models.DeviceEventRecord{}).Error
}
