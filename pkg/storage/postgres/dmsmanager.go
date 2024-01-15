package postgres

import (
	"context"

	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/resources"
	"github.com/lamassuiot/lamassuiot/v2/pkg/storage"
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
	return db.querier.Count([]gormWhereParams{})
}

func (db *PostgresDMSManagerStore) SelectAll(ctx context.Context, exhaustiveRun bool, applyFunc func(models.DMS), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error) {
	return db.querier.SelectAll(queryParams, []gormWhereParams{}, exhaustiveRun, applyFunc)
}

func (db *PostgresDMSManagerStore) SelectExists(ctx context.Context, ID string) (bool, *models.DMS, error) {
	return db.querier.SelectExists(ID, nil)
}

func (db *PostgresDMSManagerStore) Update(ctx context.Context, DMS *models.DMS) (*models.DMS, error) {
	return db.querier.Update(DMS, DMS.ID)
}

func (db *PostgresDMSManagerStore) Insert(ctx context.Context, DMS *models.DMS) (*models.DMS, error) {
	return db.querier.Insert(DMS, DMS.ID)
}
