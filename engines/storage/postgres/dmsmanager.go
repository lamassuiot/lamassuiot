package postgres

import (
	"context"

	"github.com/lamassuiot/lamassuiot/v2/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v2/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/core/pkg/resources"
	"gorm.io/gorm"
)

type PostgresDMSManagerStore struct {
	db      *gorm.DB
	querier *postgresDBQuerier[models.DMS]
}

func NewDMSManagerRepository(db *gorm.DB) (storage.DMSRepo, error) {
	querier, err := CheckAndCreateTable(db, "dms", "id", models.DMS{})
	if err != nil {
		return nil, err
	}

	return &PostgresDMSManagerStore{
		db:      db,
		querier: querier,
	}, nil
}

func (db *PostgresDMSManagerStore) Count(ctx context.Context) (int, error) {
	return db.querier.Count(ctx, []gormWhereParams{})
}

func (db *PostgresDMSManagerStore) SelectAll(ctx context.Context, exhaustiveRun bool, applyFunc func(models.DMS), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error) {
	return db.querier.SelectAll(ctx, queryParams, []gormWhereParams{}, exhaustiveRun, applyFunc)
}

func (db *PostgresDMSManagerStore) SelectExists(ctx context.Context, ID string) (bool, *models.DMS, error) {
	return db.querier.SelectExists(ctx, ID, nil)
}

func (db *PostgresDMSManagerStore) Update(ctx context.Context, DMS *models.DMS) (*models.DMS, error) {
	return db.querier.Update(ctx, DMS, DMS.ID)
}

func (db *PostgresDMSManagerStore) Insert(ctx context.Context, DMS *models.DMS) (*models.DMS, error) {
	return db.querier.Insert(ctx, DMS, DMS.ID)
}
