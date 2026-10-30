package postgres

import (
	"context"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type PostgresDeviceEventsStore struct {
	db      *gorm.DB
	querier *DBQuerier[models.DeviceEventRecord]
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
	opts := []GormExtraOps{
		{Query: "device_id = ?", AdditionalWhere: []any{deviceID}},
	}

	return db.querier.SelectAll(ctx, req.QueryParams, opts, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *PostgresDeviceEventsStore) DeleteByDeviceID(ctx context.Context, deviceID string) error {
	tenantID, scoped, err := db.querier.tenantScope(ctx)
	if err != nil {
		return err
	}

	q := db.db.WithContext(ctx).Where("device_id = ?", deviceID)
	if scoped {
		q = q.Where(db.querier.tenantIDColumn()+" = ?", tenantID)
	}

	return q.Delete(&models.DeviceEventRecord{}).Error
}
