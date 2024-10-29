package postgres

import (
	"context"

	"github.com/lamassuiot/lamassuiot/v2/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v2/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/core/pkg/resources"
	"gorm.io/gorm"
)

type PostgresDeviceManagerStore struct {
	db      *gorm.DB
	querier *postgresDBQuerier[models.Device]
}

func NewDeviceManagerRepository(db *gorm.DB) (storage.DeviceManagerRepo, error) {
	querier, err := CheckAndCreateTable(db, "devices", "id", models.Device{})
	if err != nil {
		return nil, err
	}

	return &PostgresDeviceManagerStore{
		db:      db,
		querier: querier,
	}, nil
}

func (db *PostgresDeviceManagerStore) Count(ctx context.Context) (int, error) {
	return db.querier.Count(ctx, []gormWhereParams{})
}

func (db *PostgresDeviceManagerStore) CountByStatus(ctx context.Context, status models.DeviceStatus) (int, error) {
	return db.querier.Count(ctx, []gormWhereParams{
		{
			query: "status = ?", extraArgs: []any{status},
		},
	})
}

func (db *PostgresDeviceManagerStore) SelectAll(ctx context.Context, exhaustiveRun bool, applyFunc func(models.Device), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error) {
	return db.querier.SelectAll(ctx, queryParams, []gormWhereParams{}, exhaustiveRun, applyFunc)
}

func (db *PostgresDeviceManagerStore) SelectByDMS(ctx context.Context, dmsID string, exhaustiveRun bool, applyFunc func(models.Device), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error) {
	opts := []gormWhereParams{
		{query: "dms_owner = ?", extraArgs: []any{dmsID}},
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
