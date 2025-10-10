package internal

import (
	"context"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

const kmsDBName = "kms_keys"

type PostgresKMSStore struct {
	db      *gorm.DB
	querier *PostgresDBQuerier[models.Key]
}

func NewKMSPostgresRepository(log *logrus.Entry, db *gorm.DB) (storage.KMSKeysRepo, error) {
	querier, err := TableQuery(log, db, kmsDBName, "id", models.Key{})
	if err != nil {
		return nil, err
	}

	return &PostgresKMSStore{
		db:      db,
		querier: querier,
	}, nil
}

func (db *PostgresKMSStore) Count(ctx context.Context) (int, error) {
	return db.querier.Count(ctx, []gormExtraOps{})
}

func (db *PostgresKMSStore) SelectAll(ctx context.Context, req storage.StorageListRequest[models.Key]) (string, error) {
	opts := []gormExtraOps{}
	return db.querier.SelectAll(ctx, req.QueryParams, opts, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *PostgresKMSStore) SelectExistsByID(ctx context.Context, id string) (bool, *models.Key, error) {
	return db.querier.SelectExists(ctx, id, nil)
}

func (db *PostgresKMSStore) Insert(ctx context.Context, kmsKey *models.Key) (*models.Key, error) {
	return db.querier.Insert(ctx, kmsKey, kmsKey.ID)
}

func (db *PostgresKMSStore) Delete(ctx context.Context, id string) error {
	return db.querier.Delete(ctx, id)
}
