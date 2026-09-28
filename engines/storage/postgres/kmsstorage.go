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
	querier *DBQuerier[models.Key]
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
	return db.querier.Count(ctx, []GormExtraOps{})
}

func (db *PostgresKMSStore) CountWithFilters(ctx context.Context, queryParams *resources.QueryParameters) (int, error) {
	if queryParams == nil {
		return db.Count(ctx)
	}

	return db.querier.CountFiltered(ctx, queryParams.Filters, []GormExtraOps{})
}

func (db *PostgresKMSStore) CountByEngineWithFilters(ctx context.Context, engineID string, queryParams *resources.QueryParameters) (int, error) {
	opts := []GormExtraOps{
		{Query: "engine_id = ?", AdditionalWhere: []any{engineID}},
	}

	if queryParams == nil {
		return db.querier.Count(ctx, opts)
	}

	return db.querier.CountFiltered(ctx, queryParams.Filters, opts)
}

func (db *PostgresKMSStore) SelectAll(ctx context.Context, req storage.StorageListRequest[models.Key]) (string, error) {
	opts := []GormExtraOps{}
	return db.querier.SelectAll(ctx, req.QueryParams, opts, req.ExhaustiveRun, req.ApplyFunc)
}

// The identity of a key is (key_id, engine_id): the same key_id can be held by several
// engines at once. DBQuerier addresses rows by a single column, so the composite-key
// operations below build their own WHERE clauses instead of going through it.
func (db *PostgresKMSStore) SelectExistsByKeyID(ctx context.Context, keyID, engineID string) (bool, *models.Key, error) {
	var elem models.Key
	tx := db.querier.Table(kmsTableName).WithContext(ctx).Where("key_id = ? AND engine_id = ?", keyID, engineID).Limit(1).Find(&elem)
	if tx.Error != nil {
		return false, nil, tx.Error
	}

	if tx.RowsAffected == 0 {
		return false, nil, nil
	}

	return true, &elem, nil
}

func (db *PostgresKMSStore) SelectByKeyID(ctx context.Context, keyID string) ([]*models.Key, error) {
	var keys []*models.Key
	tx := db.querier.Table(kmsTableName).WithContext(ctx).Where("key_id = ?", keyID).Order("engine_id").Find(&keys)
	if tx.Error != nil {
		return nil, tx.Error
	}

	return keys, nil
}

func (db *PostgresKMSStore) SelectExistsByName(ctx context.Context, name string) (bool, *models.Key, error) {
	col := "name"
	return db.querier.SelectExists(ctx, name, &col)
}

func (db *PostgresKMSStore) SelectExistsByAlias(ctx context.Context, alias string) (bool, *models.Key, error) {
	var elem models.Key
	query := db.querier.Table(kmsTableName).WithContext(ctx)
	// The monolithic deployment runs this repository on SQLite, which has neither jsonb nor
	// the containment operator.
	if isSQLite(db.querier.DB) {
		query = query.Where("EXISTS (SELECT 1 FROM json_each(aliases) WHERE value = ?)", alias)
	} else {
		query = query.Where("aliases @> ?::jsonb", fmt.Sprintf(`["%s"]`, alias))
	}

	tx := query.Limit(1).Find(&elem)
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
	tx := db.querier.Session(&gorm.Session{FullSaveAssociations: true}).Table(kmsTableName).WithContext(ctx).
		Where("key_id = ? AND engine_id = ?", kmsKey.KeyID, kmsKey.EngineID).Save(kmsKey)
	if tx.Error != nil {
		return nil, tx.Error
	}

	if tx.RowsAffected != 1 {
		return nil, gorm.ErrRecordNotFound
	}

	return kmsKey, nil
}

func (db *PostgresKMSStore) Delete(ctx context.Context, keyID, engineID string) error {
	tx := db.querier.Table(kmsTableName).WithContext(ctx).
		Where("key_id = ? AND engine_id = ?", keyID, engineID).Delete(nil)
	if tx.Error != nil {
		return tx.Error
	}

	if tx.RowsAffected != 1 {
		return gorm.ErrRecordNotFound
	}

	return nil
}
