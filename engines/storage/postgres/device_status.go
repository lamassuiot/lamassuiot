package postgres

import (
	"context"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type PostgresDeviceStatusStore struct {
	db      *gorm.DB
	querier *postgresDBQuerier[models.DeviceStatus]
}

func NewDeviceStatusRepository(logger *logrus.Entry, db *gorm.DB) (storage.DeviceStatusRepo, error) {
	querier, err := TableQuery(logger, db, "device_status_updates", []string{"timestamp", "device_id"}, models.DeviceStatus{})
	if err != nil {
		return nil, err
	}

	return &PostgresDeviceStatusStore{
		db:      db,
		querier: querier,
	}, nil
}

func (db *PostgresDeviceStatusStore) Select(ctx context.Context, deviceID string, exhaustiveRun bool, applyFunc func(models.DeviceStatus), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error) {
	opts := []gormExtraOps{
		{query: "device_id = ?", additionalWhere: []any{deviceID}},
	}
	return db.querier.SelectAll(ctx, queryParams, opts, exhaustiveRun, applyFunc)
}

func (db *PostgresDeviceStatusStore) Insert(ctx context.Context, device *models.DeviceStatus) (*models.DeviceStatus, error) {
	return db.querier.Insert(ctx, device)
}
