//go:build experimental
// +build experimental

package sqlite

import (
	"context"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"

	"gorm.io/gorm"
)

type SQLiteDMSManagerStore struct {
	db      *gorm.DB
	querier *sqliteDBQuerier[models.DMS]
}

func NewDMSManagerRepository(db *gorm.DB) (storage.DMSRepo, error) {
	querier, err := TableQuery(db, "dms", "id", models.DMS{})
	if err != nil {
		return nil, err
	}

	return &SQLiteDMSManagerStore{
		db:      db,
		querier: querier,
	}, nil
}

func (db *SQLiteDMSManagerStore) Count(ctx context.Context) (int, error) {
	return db.querier.Count(ctx, []gormWhereParams{})
}

func (db *SQLiteDMSManagerStore) SelectAll(ctx context.Context, exhaustiveRun bool, applyFunc func(models.DMS), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error) {
	return db.querier.SelectAll(ctx, queryParams, []gormWhereParams{}, exhaustiveRun, applyFunc)
}

func (db *SQLiteDMSManagerStore) SelectExists(ctx context.Context, ID string) (bool, *models.DMS, error) {
	return db.querier.SelectExists(ctx, ID, nil)
}

func (db *SQLiteDMSManagerStore) Update(ctx context.Context, DMS *models.DMS) (*models.DMS, error) {
	return db.querier.Update(ctx, DMS, DMS.ID)
}

func (db *SQLiteDMSManagerStore) Insert(ctx context.Context, DMS *models.DMS) (*models.DMS, error) {
	return db.querier.Insert(ctx, DMS, DMS.ID)
}
