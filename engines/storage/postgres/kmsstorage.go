package postgres

import (
	"context"
	"fmt"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

const kmsTableName = "kms_keys"

type PostgresKMSStore struct {
	db      *gorm.DB
	querier *postgresDBQuerier[models.Key]
}

func NewKMSPostgresRepository(log *logrus.Entry, db *gorm.DB) (storage.KMSKeysRepo, error) {
	querier, err := TableQuery(log, db, kmsTableName, "key_id", models.Key{})
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

func (db *PostgresKMSStore) CountWithFilters(ctx context.Context, queryParams *resources.QueryParameters) (int, error) {
	if queryParams == nil {
		return db.Count(ctx)
	}

	return db.querier.CountFiltered(ctx, queryParams.Filters, []gormExtraOps{})
}

func (db *PostgresKMSStore) CountByEngineWithFilters(ctx context.Context, engineID string, queryParams *resources.QueryParameters) (int, error) {
	opts := []gormExtraOps{
		{query: "engine_id = ?", additionalWhere: []any{engineID}},
	}

	if queryParams == nil {
		return db.querier.Count(ctx, opts)
	}

	return db.querier.CountFiltered(ctx, queryParams.Filters, opts)
}

func (db *PostgresKMSStore) SelectAll(ctx context.Context, req storage.StorageListRequest[models.Key]) (string, error) {
	opts := []gormExtraOps{}
	return db.querier.SelectAll(ctx, req.QueryParams, opts, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *PostgresKMSStore) SelectExistsByKeyID(ctx context.Context, id string) (bool, *models.Key, error) {
	return db.querier.SelectExists(ctx, id, nil)
}

func (db *PostgresKMSStore) SelectExistsByName(ctx context.Context, name string) (bool, *models.Key, error) {
	col := "name"
	return db.querier.SelectExists(ctx, name, &col)
}

func (db *PostgresKMSStore) SelectExistsByAlias(ctx context.Context, alias string) (bool, *models.Key, error) {
	var elem models.Key
	tx := db.querier.Table(kmsTableName).WithContext(ctx).Where("aliases @> ?::jsonb", fmt.Sprintf(`["%s"]`, alias)).Limit(1).Find(&elem)
	if tx.Error != nil {
		return false, nil, tx.Error
	}

	if tx.RowsAffected == 0 {
		return false, nil, nil // No record found, but no error
	}

	return true, &elem, nil
}

func (db *PostgresKMSStore) Insert(ctx context.Context, kmsKey *models.Key) (*models.Key, error) {
	return db.querier.Insert(ctx, kmsKey, kmsKey.KeyID)
}

func (db *PostgresKMSStore) Update(ctx context.Context, kmsKey *models.Key) (*models.Key, error) {
	return db.querier.Update(ctx, kmsKey, kmsKey.KeyID)
}

func (db *PostgresKMSStore) Delete(ctx context.Context, id string) error {
	return db.querier.Delete(ctx, id)
}
