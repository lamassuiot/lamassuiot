package postgres

import (
	"context"
	"errors"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
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
	// The same key can live in several engines, so key_id alone is not unique
	querier.uniqueColumns = []string{"key_id", "engine_id"}

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
	var rowsAffected int64
	err := db.tenantTable(ctx, func(q *gorm.DB, _ string, _ bool) error {
		result := q.Where("key_id = ? AND engine_id = ?", keyID, engineID).Limit(1).Find(&elem)
		rowsAffected = result.RowsAffected
		return result.Error
	})
	if err != nil {
		return false, nil, err
	}

	if rowsAffected == 0 {
		return false, nil, nil
	}

	return true, &elem, nil
}

func (db *PostgresKMSStore) SelectByKeyID(ctx context.Context, keyID string) ([]*models.Key, error) {
	var keys []*models.Key
	err := db.tenantTable(ctx, func(q *gorm.DB, _ string, _ bool) error {
		return q.Where("key_id = ?", keyID).Order("engine_id").Find(&keys).Error
	})
	if err != nil {
		return nil, err
	}

	return keys, nil
}

func (db *PostgresKMSStore) SelectExistsByName(ctx context.Context, name string) (bool, *models.Key, error) {
	col := "name"
	return db.querier.SelectExists(ctx, name, &col)
}

func (db *PostgresKMSStore) SelectExistsByAlias(ctx context.Context, alias string) (bool, *models.Key, error) {
	var elem models.Key
	var rowsAffected int64
	err := db.tenantTable(ctx, func(q *gorm.DB, _ string, _ bool) error {
		result := q.Where("aliases @> ?::jsonb", jsonStringArray(alias)).Limit(1).Find(&elem)
		rowsAffected = result.RowsAffected
		return result.Error
	})
	if err != nil {
		return false, nil, err
	}

	if rowsAffected == 0 {
		return false, nil, nil // No record found, but no error
	}

	return true, &elem, nil
}

func (db *PostgresKMSStore) Insert(ctx context.Context, kmsKey *models.Key) (*models.Key, error) {
	return db.querier.Insert(ctx, kmsKey, kmsKey.KeyID)
}

func (db *PostgresKMSStore) Update(ctx context.Context, kmsKey *models.Key) (*models.Key, error) {
	var rowsAffected int64
	err := db.tenantTable(ctx, func(q *gorm.DB, tenantID string, scoped bool) error {
		if scoped {
			setTenantID(kmsKey, tenantID)
		}
		result := q.Session(&gorm.Session{FullSaveAssociations: true}).
			Where("key_id = ? AND engine_id = ?", kmsKey.KeyID, kmsKey.EngineID).Select("*").Updates(kmsKey)
		rowsAffected = result.RowsAffected
		return result.Error
	})
	if err != nil {
		return nil, err
	}

	if rowsAffected != 1 {
		return nil, gorm.ErrRecordNotFound
	}

	return kmsKey, nil
}

func (db *PostgresKMSStore) Delete(ctx context.Context, keyID, engineID string) error {
	var rowsAffected int64
	err := db.tenantTable(ctx, func(q *gorm.DB, _ string, _ bool) error {
		result := q.Where("key_id = ? AND engine_id = ?", keyID, engineID).Delete(nil)
		rowsAffected = result.RowsAffected
		return result.Error
	})
	if errors.Is(err, gorm.ErrForeignKeyViolated) {
		return errs.ErrKeyInUse
	}
	if err != nil {
		return err
	}

	if rowsAffected != 1 {
		return gorm.ErrRecordNotFound
	}

	return nil
}

func (db *PostgresKMSStore) tenantTable(ctx context.Context, fn func(q *gorm.DB, tenantID string, scoped bool) error) error {
	tenantID, scoped, err := db.querier.tenantScope(ctx)
	if err != nil {
		return err
	}

	return db.querier.withTenantScopedTx(ctx, tenantID, scoped, func(tx *gorm.DB) error {
		q := tx.Table(kmsTableName)
		if scoped {
			q = q.Where(db.querier.tenantIDColumn()+" = ?", tenantID)
		}
		return fn(q, tenantID, scoped)
	})
}

func (db *PostgresKMSStore) DeleteWith(ctx context.Context, keyID, engineID string, fn func() error) error {
	tenantID, scoped, err := db.querier.tenantScope(ctx)
	if err != nil {
		return err
	}

	run := func(tx *gorm.DB) error {
		q := tx.Table(kmsTableName).Where("key_id = ? AND engine_id = ?", keyID, engineID)
		if scoped {
			q = q.Where(db.querier.tenantIDColumn()+" = ?", tenantID)
		}
		res := q.Delete(nil)
		if errors.Is(res.Error, gorm.ErrForeignKeyViolated) {
			return errs.ErrKeyInUse
		}
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected != 1 {
			return errs.ErrKeyNotFound
		}
		return fn()
	}

	if scoped {
		return withTenantIDTransaction(ctx, db.db, tenantID, run)
	}
	return db.db.WithContext(ctx).Transaction(run)
}

// RenameKey runs under a lock shared by every rename, so KMS instances starting at once do not rename the
// same key twice. The certificates that reference the key follow it through their foreign key, which
// cascades updates.
func (db *PostgresKMSStore) RenameKey(ctx context.Context, engineID, oldKeyID, newKeyID string, renameInEngine func() error) (bool, error) {
	renamed := false
	err := db.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec(`SELECT pg_advisory_xact_lock(hashtext('lamassu.kms.rename-key'))`).Error; err != nil {
			return err
		}

		var found int64
		if err := tx.Table(kmsTableName).Where("key_id = ? AND engine_id = ?", oldKeyID, engineID).Count(&found).Error; err != nil {
			return err
		}
		if found == 0 {
			return nil
		}

		if err := renameInEngine(); err != nil {
			return err
		}

		res := tx.Exec(`UPDATE kms_keys SET key_id = ?, aliases = COALESCE(aliases, '[]'::jsonb) || ?::jsonb
			WHERE key_id = ? AND engine_id = ?`, newKeyID, jsonStringArray(oldKeyID), oldKeyID, engineID)
		if res.Error != nil {
			return res.Error
		}
		renamed = res.RowsAffected == 1
		return nil
	})
	return renamed && err == nil, err
}
