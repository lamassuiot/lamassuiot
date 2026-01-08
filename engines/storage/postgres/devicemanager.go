package postgres

import (
	"context"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type PostgresDeviceManagerStore struct {
	db      *gorm.DB
	querier *postgresDBQuerier[models.Device]
}

func NewDeviceManagerRepository(logger *logrus.Entry, db *gorm.DB) (storage.DeviceManagerRepo, error) {
	querier, err := TableQuery(logger, db, "devices", "id", models.Device{})
	if err != nil {
		return nil, err
	}

	return &PostgresDeviceManagerStore{
		db:      db,
		querier: querier,
	}, nil
}

func (db *PostgresDeviceManagerStore) Count(ctx context.Context, queryParams *resources.QueryParameters) (int, error) {
	filters := []resources.FilterOption{}
	if queryParams != nil {
		filters = queryParams.Filters
	}
	return db.querier.CountFiltered(ctx, filters, []gormExtraOps{})
}

func (db *PostgresDeviceManagerStore) SelectAll(ctx context.Context, exhaustiveRun bool, applyFunc func(models.Device), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error) {
	return db.querier.SelectAll(ctx, queryParams, []gormExtraOps{}, exhaustiveRun, applyFunc)
}

func (db *PostgresDeviceManagerStore) SelectByDMS(ctx context.Context, dmsID string, exhaustiveRun bool, applyFunc func(models.Device), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error) {
	opts := []gormExtraOps{
		{query: "dms_owner = ?", additionalWhere: []any{dmsID}},
	}
	return db.querier.SelectAll(ctx, queryParams, opts, exhaustiveRun, applyFunc)
}

func (db *PostgresDeviceManagerStore) SelectExists(ctx context.Context, ID string) (bool, *models.Device, error) {
	return db.querier.SelectExists(ctx, ID, nil)
}

func (db *PostgresDeviceManagerStore) Update(ctx context.Context, device *models.Device) (*models.Device, error) {
	return db.querier.Update(ctx, device, device.ID)
}

func (db *PostgresDeviceManagerStore) Insert(ctx context.Context, device *models.Device) (*models.Device, error) {
	return db.querier.Insert(ctx, device, device.ID)
}

func (db *PostgresDeviceManagerStore) Delete(ctx context.Context, ID string) error {
	return db.querier.Delete(ctx, ID)
}
