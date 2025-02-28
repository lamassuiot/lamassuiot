package postgres

import (
	"context"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type PostgresAsymmetricKMSStore struct {
	db      *gorm.DB
	querier *postgresDBQuerier[models.KeyPair]
}

func NewAsymmetricKMSPostgresRepository(log *logrus.Entry, db *gorm.DB) (storage.AsymmetricKMSRepo, error) {
	querier, err := TableQuery(log, db, KMS_DB_NAME, "key_id", models.KeyPair{})
	if err != nil {
		return nil, err
	}

	return &PostgresAsymmetricKMSStore{
		db:      db,
		querier: querier,
	}, nil
}

func (db *PostgresAsymmetricKMSStore) Insert(ctx context.Context, KeyPair *models.KeyPair) (*models.KeyPair, error) {
	return db.querier.Insert(ctx, KeyPair, KeyPair.KeyID)
}

func (db *PostgresAsymmetricKMSStore) SelectExists(ctx context.Context, id string) (bool, *models.KeyPair, error) {
	return db.querier.SelectExists(ctx, id, nil)
}

func (db *PostgresAsymmetricKMSStore) Update(ctx context.Context, kp *models.KeyPair) (*models.KeyPair, error) {
	return db.querier.Update(ctx, kp, kp.KeyID)
}

func (db *PostgresAsymmetricKMSStore) Delete(ctx context.Context, reqID string) error {
	return db.querier.Delete(ctx, reqID)
}

func (db *PostgresAsymmetricKMSStore) Count(ctx context.Context) (int, error) {
	return db.querier.Count(ctx, []gormExtraOps{})
}

func (db *PostgresAsymmetricKMSStore) SelectAll(ctx context.Context, req storage.StorageListRequest[models.KeyPair]) (string, error) {
	return db.querier.SelectAll(ctx, req.QueryParams, []gormExtraOps{}, req.ExhaustiveRun, req.ApplyFunc)
}
