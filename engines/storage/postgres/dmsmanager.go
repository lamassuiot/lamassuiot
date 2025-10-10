package postgres

import (
	"context"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type PostgresDMSManagerStore struct {
	db      *gorm.DB
	querier *PostgresDBQuerier[models.DMS]
}

func NewDMSManagerRepository(logger *logrus.Entry, db *gorm.DB) (storage.DMSRepo, error) {
	querier, err := TableQuery(logger, db, "dms", "id", models.DMS{})
	if err != nil {
		return nil, err
	}

	return &PostgresDMSManagerStore{
		db:      db,
		querier: querier,
	}, nil
}

func (db *PostgresDMSManagerStore) Count(ctx context.Context) (int, error) {
	return db.querier.Count(ctx, []gormExtraOps{})
}

func (db *PostgresDMSManagerStore) SelectAll(ctx context.Context, exhaustiveRun bool, applyFunc func(models.DMS), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error) {
	return db.querier.SelectAll(ctx, queryParams, []gormExtraOps{}, exhaustiveRun, applyFunc)
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

func (db *PostgresDMSManagerStore) Delete(ctx context.Context, ID string) error {
	return db.querier.Delete(ctx, ID)
}
