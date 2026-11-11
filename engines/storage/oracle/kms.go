package oracle

import (
	"context"
	"errors"
	"regexp"
	"strings"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
	oracleerrors "github.com/oracle/go-oracledb/v26/oracle/errors"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const kmsTableName = "kms_keys"

// Oracle stores empty strings as NULL. Keep an explicit reversible encoding so
// the NOT NULL name column can still represent the empty value used by Lamassu.
const emptyKMSKeyName = "~lamassu-oracle-empty-kms-key-name~"

type kmsStore struct{ db *gorm.DB }

var _ storage.KMSKeysRepo = (*kmsStore)(nil)

var kmsFilterFields = map[string]struct{}{
	"key_id": {}, "engine_id": {}, "name": {}, "aliases": {}, "has_private_key": {},
	"algorithm": {}, "size": {}, "public_key": {}, "creation_ts": {}, "tags": {}, "metadata": {},
}

func (s *kmsStore) Count(ctx context.Context) (int, error) {
	var count int64
	if err := s.db.WithContext(ctx).Table(kmsTableName).Count(&count).Error; err != nil {
		return -1, err
	}
	return int(count), nil
}

func (s *kmsStore) CountWithFilters(ctx context.Context, params *resources.QueryParameters) (int, error) {
	return s.countFiltered(ctx, nil, params)
}

func (s *kmsStore) CountByEngineWithFilters(ctx context.Context, engineID string, params *resources.QueryParameters) (int, error) {
	return s.countFiltered(ctx, &engineID, params)
}

func (s *kmsStore) countFiltered(ctx context.Context, engineID *string, params *resources.QueryParameters) (int, error) {
	tx := s.db.WithContext(ctx).Table(kmsTableName)
	if engineID != nil {
		tx = tx.Where("engine_id = ?", *engineID)
	}
	if params != nil {
		paramsCopy := *params
		paramsCopy.Filters = encodeKMSNameFilters(params.Filters)
		var err error
		tx, err = applyFilters(tx, paramsCopy.Filters, kmsFilterFields)
		if err != nil {
			return -1, err
		}
	}
	var count int64
	if err := tx.Count(&count).Error; err != nil {
		return -1, err
	}
	return int(count), nil
}

var kmsSortFields = map[string]struct{}{
	"key_id": {}, "engine_id": {}, "name": {}, "has_private_key": {}, "algorithm": {}, "size": {}, "creation_ts": {}, "metadata": {},
}

func (s *kmsStore) SelectAll(ctx context.Context, req storage.StorageListRequest[models.Key]) (string, error) {
	apply := req.ApplyFunc
	if apply != nil {
		req.ApplyFunc = func(key models.Key) {
			key.Name = decodeKMSKeyName(key.Name)
			apply(key)
		}
	}
	return listRows(s.db.WithContext(ctx).Table(kmsTableName), req, kmsFilterFields, kmsSortFields, nil, nil,
		[]string{"key_id", "engine_id"}, func(key models.Key) []any { return []any{key.KeyID, key.EngineID} }, encodeKMSNameFilters)
}

func (s *kmsStore) SelectExistsByKeyID(ctx context.Context, keyID, engineID string) (bool, *models.Key, error) {
	var key models.Key
	tx := s.db.WithContext(ctx).Table(kmsTableName).Where("key_id = ? AND engine_id = ?", keyID, engineID).Limit(1).Find(&key)
	if tx.Error != nil {
		return false, nil, tx.Error
	}
	if tx.RowsAffected == 0 {
		return false, nil, nil
	}
	key.Name = decodeKMSKeyName(key.Name)
	return true, &key, nil
}

func (s *kmsStore) SelectByKeyID(ctx context.Context, keyID string) ([]*models.Key, error) {
	var keys []*models.Key
	err := s.db.WithContext(ctx).Table(kmsTableName).Where("key_id = ?", keyID).Order("engine_id").Find(&keys).Error
	for _, key := range keys {
		key.Name = decodeKMSKeyName(key.Name)
	}
	return keys, err
}

func (s *kmsStore) SelectExistsByAlias(ctx context.Context, alias string) (bool, *models.Key, error) {
	var key models.Key
	tx := s.db.WithContext(ctx).Table(kmsTableName).Where(jsonArrayContains{column: clause.Column{Table: clause.CurrentTable, Name: "aliases"}, value: alias}).Limit(1).Find(&key)
	if tx.Error != nil {
		return false, nil, tx.Error
	}
	if tx.RowsAffected == 0 {
		return false, nil, nil
	}
	key.Name = decodeKMSKeyName(key.Name)
	return true, &key, nil
}

func (s *kmsStore) Insert(ctx context.Context, key *models.Key) (*models.Key, error) {
	persisted := *key
	persisted.Name = encodeKMSKeyName(persisted.Name)
	if err := s.db.WithContext(ctx).Table(kmsTableName).Create(&persisted).Error; err != nil {
		return nil, err
	}
	return key, nil
}

func (s *kmsStore) Update(ctx context.Context, key *models.Key) (*models.Key, error) {
	persisted := *key
	persisted.Name = encodeKMSKeyName(persisted.Name)
	tx := s.db.WithContext(ctx).Table(kmsTableName).Where("key_id = ? AND engine_id = ?", key.KeyID, key.EngineID).Select("*").Updates(&persisted)
	if tx.Error != nil {
		return nil, tx.Error
	}
	if tx.RowsAffected != 1 {
		return nil, gorm.ErrRecordNotFound
	}
	return key, nil
}

func encodeKMSKeyName(name string) string {
	if name == "" {
		return emptyKMSKeyName
	}
	if strings.HasPrefix(name, emptyKMSKeyName) {
		return emptyKMSKeyName + name
	}
	return name
}

func decodeKMSKeyName(name string) string {
	if name == emptyKMSKeyName {
		return ""
	}
	if strings.HasPrefix(name, emptyKMSKeyName+emptyKMSKeyName) {
		return strings.TrimPrefix(name, emptyKMSKeyName)
	}
	return name
}

func encodeKMSNameFilters(filters []resources.FilterOption) []resources.FilterOption {
	filters = append([]resources.FilterOption(nil), filters...)
	for i := range filters {
		field := strings.ReplaceAll(filters[i].Field, ".", "_")
		if field != "name" {
			continue
		}
		switch filters[i].FilterOperation {
		case resources.StringEqual, resources.StringEqualIgnoreCase, resources.EnumEqual,
			resources.StringNotEqual, resources.StringNotEqualIgnoreCase, resources.EnumNotEqual:
			filters[i].Value = encodeKMSKeyName(filters[i].Value)
		case resources.StringIn, resources.StringInIgnoreCase, resources.StringNotIn, resources.StringNotInIgnoreCase, resources.EnumIn:
			values := strings.Split(filters[i].Value, ",")
			for j := range values {
				if values[j] != "" {
					values[j] = encodeKMSKeyName(values[j])
				}
			}
			filters[i].Value = strings.Join(values, ",")
		}
	}
	return filters
}

var certKeyConstraint = regexp.MustCompile(`(?i)\([^)]*\blamassu_cert_key_fk\)`)

func keyDeleteError(err error) error {
	var sqlErr oracleerrors.SQLError
	if errors.As(err, &sqlErr) && sqlErr.ErrorCode() == "ORA-02292" && certKeyConstraint.MatchString(sqlErr.Error()) {
		return errs.ErrKeyInUse
	}
	return err
}

func (s *kmsStore) Delete(ctx context.Context, keyID, engineID string) error {
	tx := s.db.WithContext(ctx).Table(kmsTableName).Where("key_id = ? AND engine_id = ?", keyID, engineID).Delete(&models.Key{})
	if tx.Error != nil {
		return keyDeleteError(tx.Error)
	}
	if tx.RowsAffected != 1 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

func (s *kmsStore) DeleteWith(ctx context.Context, keyID, engineID string, fn func() error) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		res := tx.Table(kmsTableName).Where("key_id = ? AND engine_id = ?", keyID, engineID).Delete(&models.Key{})
		if res.Error != nil {
			return keyDeleteError(res.Error)
		}
		if res.RowsAffected != 1 {
			return errs.ErrKeyNotFound
		}
		return fn()
	})
}

func (s *kmsStore) RenameKey(ctx context.Context, engineID, oldKeyID, newKeyID string, fn func() error) (bool, error) {
	return renameKey(ctx, s.db, engineID, oldKeyID, newKeyID, fn)
}
