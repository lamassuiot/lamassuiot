//go:build experimental
// +build experimental

package sqlite

import (
	"context"

	"github.com/lamassuiot/lamassuiot/v2/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v2/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/core/pkg/resources"

	"gorm.io/gorm"
)

type SQLiteDeviceManagerStore struct {
	db      *gorm.DB
	querier *sqliteDBQuerier[models.Device]
}

func NewDeviceManagerRepository(db *gorm.DB) (storage.DeviceManagerRepo, error) {
	querier, err := CheckAndCreateTable(db, "devices", "id", models.Device{})
	if err != nil {
		return nil, err
	}

	return &SQLiteDeviceManagerStore{
		db:      db,
		querier: querier,
	}, nil
}

func (db *SQLiteDeviceManagerStore) Count(ctx context.Context) (int, error) {
	return db.querier.Count(ctx, []gormWhereParams{})
}

func (db *SQLiteDeviceManagerStore) CountByStatus(ctx context.Context, status models.DeviceStatus) (int, error) {
	return db.querier.Count(ctx, []gormWhereParams{
		{
			query: "status = ?", extraArgs: []any{status},
		},
	})
}

func (db *SQLiteDeviceManagerStore) SelectAll(ctx context.Context, exhaustiveRun bool, applyFunc func(models.Device), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error) {
	return db.querier.SelectAll(ctx, queryParams, []gormWhereParams{}, exhaustiveRun, applyFunc)
}

func (db *SQLiteDeviceManagerStore) SelectByDMS(ctx context.Context, dmsID string, exhaustiveRun bool, applyFunc func(models.Device), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error) {
	opts := []gormWhereParams{
		{query: "dms_owner = ?", extraArgs: []any{dmsID}},
	}
	return db.querier.SelectAll(ctx, queryParams, opts, exhaustiveRun, applyFunc)
}

func (db *SQLiteDeviceManagerStore) SelectExists(ctx context.Context, ID string) (bool, *models.Device, error) {
	return db.querier.SelectExists(ctx, ID, nil)
}

func (db *SQLiteDeviceManagerStore) Update(ctx context.Context, device *models.Device) (*models.Device, error) {
	return db.querier.Update(ctx, device, device.ID)
}

func (db *SQLiteDeviceManagerStore) Insert(ctx context.Context, device *models.Device) (*models.Device, error) {
	return db.querier.Insert(ctx, device, device.ID)
}
