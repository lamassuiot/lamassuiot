package oracle

import (
	"context"
	"regexp"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
	"gorm.io/gorm"
)

type dmsStore struct{ db *gorm.DB }

var _ storage.DMSRepo = (*dmsStore)(nil)
var dmsPK = regexp.MustCompile(`(?i)\([^)]*\blamassu_dms_pk\)`)
var dmsFilterFields = map[string]struct{}{"id": {}, "name": {}, "creation_date": {}, "metadata": {}, "settings": {}}
var dmsSortFields = map[string]struct{}{"id": {}, "name": {}, "creation_date": {}}

func (s *dmsStore) Count(ctx context.Context) (int, error) { return s.CountWithFilters(ctx, nil) }

func (s *dmsStore) CountWithFilters(ctx context.Context, params *resources.QueryParameters) (int, error) {
	tx := s.db.WithContext(ctx).Table("dms")
	if params != nil {
		var err error
		tx, err = applyFilters(tx, params.Filters, dmsFilterFields)
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

func (s *dmsStore) SelectAll(ctx context.Context, exhaustive bool, apply func(models.DMS), params *resources.QueryParameters, opts map[string]any) (string, error) {
	req := storage.StorageListRequest[models.DMS]{ExhaustiveRun: exhaustive, ApplyFunc: apply, QueryParams: params, ExtraOpts: opts}
	return listRows(s.db.WithContext(ctx).Table("dms"), req, dmsFilterFields, dmsSortFields, nil, nil, []string{"id"}, func(dms models.DMS) []any { return []any{dms.ID} })
}

func (s *dmsStore) SelectExists(ctx context.Context, id string) (bool, *models.DMS, error) {
	var dms models.DMS
	tx := s.db.WithContext(ctx).Table("dms").Where("id = ?", id).Limit(1).Find(&dms)
	if tx.Error != nil {
		return false, nil, tx.Error
	}
	if tx.RowsAffected == 0 {
		return false, nil, nil
	}
	return true, &dms, nil
}

func (s *dmsStore) Insert(ctx context.Context, dms *models.DMS) (*models.DMS, error) {
	if err := s.db.WithContext(ctx).Table("dms").Create(dms).Error; err != nil {
		if constraintError(err, "ORA-00001", dmsPK) {
			return nil, gorm.ErrDuplicatedKey
		}
		return nil, err
	}
	return dms, nil
}

func (s *dmsStore) Update(ctx context.Context, dms *models.DMS) (*models.DMS, error) {
	tx := s.db.WithContext(ctx).Table("dms").Where("id = ?", dms.ID).Select("*").Updates(dms)
	if tx.Error != nil {
		return nil, tx.Error
	}
	if tx.RowsAffected != 1 {
		return nil, gorm.ErrRecordNotFound
	}
	return dms, nil
}

func (s *dmsStore) Delete(ctx context.Context, id string) error {
	tx := s.db.WithContext(ctx).Table("dms").Where("id = ?", id).Delete(&models.DMS{})
	if tx.Error != nil {
		return tx.Error
	}
	if tx.RowsAffected != 1 {
		return gorm.ErrRecordNotFound
	}
	return nil
}
