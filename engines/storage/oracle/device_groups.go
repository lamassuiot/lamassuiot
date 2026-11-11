package oracle

import (
	"context"
	"fmt"
	"regexp"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"gorm.io/gorm"
)

type deviceGroupStore struct{ db *gorm.DB }

var _ storage.DeviceGroupsRepo = (*deviceGroupStore)(nil)
var _ storage.DeviceManagerRepo = (*deviceStore)(nil)
var groupUniqueConstraint = regexp.MustCompile(`(?i)\([^)]*\blamassu_group_(?:pk|name_uk)\)`)
var groupFields = map[string]struct{}{"id": {}, "name": {}, "description": {}, "parent_id": {}, "criteria": {}, "created_at": {}, "updated_at": {}}
var groupSortFields = map[string]struct{}{"id": {}, "name": {}, "parent_id": {}, "created_at": {}, "updated_at": {}}

func (s *deviceStore) DeviceGroups() storage.DeviceGroupsRepo { return &deviceGroupStore{db: s.db} }

func (s *deviceGroupStore) Count(ctx context.Context) (int, error) {
	var count int64
	if err := s.db.WithContext(ctx).Table("device_groups").Count(&count).Error; err != nil {
		return -1, err
	}
	return int(count), nil
}

func (s *deviceGroupStore) SelectAll(ctx context.Context, req storage.StorageListRequest[models.DeviceGroup]) (string, error) {
	return listRows(s.db.WithContext(ctx).Table("device_groups"), req, groupFields, groupSortFields, nil, nil, []string{"id"}, func(group models.DeviceGroup) []any { return []any{group.ID} })
}

func (s *deviceGroupStore) SelectByID(ctx context.Context, id string) (bool, *models.DeviceGroup, error) {
	var group models.DeviceGroup
	tx := s.db.WithContext(ctx).Table("device_groups").Where("id = ?", id).Limit(1).Find(&group)
	if tx.Error != nil {
		return false, nil, tx.Error
	}
	if tx.RowsAffected == 0 {
		return false, nil, nil
	}
	return true, &group, nil
}

func (s *deviceGroupStore) SelectAncestors(ctx context.Context, id string) ([]*models.DeviceGroup, error) {
	var groups []*models.DeviceGroup
	// The starting group is included, matching the PostgreSQL repository.
	query := `SELECT id, name, description, parent_id, criteria, created_at, updated_at FROM device_groups
		START WITH id = ? CONNECT BY NOCYCLE PRIOR parent_id = id ORDER BY created_at ASC`
	if err := s.db.WithContext(ctx).Raw(query, id).Find(&groups).Error; err != nil {
		return nil, err
	}
	return groups, nil
}

// All parent changes and deletions acquire the same row lock across service
// instances. The lock remains held through validation and the write.
func (s *deviceGroupStore) locked(ctx context.Context, fn func(*gorm.DB) error) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var id string
		if err := tx.Raw("SELECT lock_id FROM lamassu_locks WHERE lock_id = ? FOR UPDATE", "device_groups").Row().Scan(&id); err != nil {
			return fmt.Errorf("lock device groups: %w", err)
		}
		return fn(tx)
	})
}

func validateGroupParent(tx *gorm.DB, group *models.DeviceGroup) error {
	if group.ParentID == nil {
		return nil
	}
	if group.ID == *group.ParentID {
		return fmt.Errorf("circular reference detected: group cannot be its own parent")
	}
	var count int64
	query := `SELECT COUNT(*) FROM (SELECT id FROM device_groups START WITH id = ? CONNECT BY NOCYCLE PRIOR parent_id = id) WHERE id = ?`
	if err := tx.Raw(query, *group.ParentID, group.ID).Row().Scan(&count); err != nil {
		return err
	}
	if count != 0 {
		return fmt.Errorf("circular reference detected: parent group is a descendant of this group")
	}
	return nil
}

func (s *deviceGroupStore) Insert(ctx context.Context, group *models.DeviceGroup) (*models.DeviceGroup, error) {
	err := s.locked(ctx, func(tx *gorm.DB) error {
		if err := validateGroupParent(tx, group); err != nil {
			return err
		}
		return tx.Table("device_groups").Create(group).Error
	})
	if constraintError(err, "ORA-00001", groupUniqueConstraint) {
		return nil, gorm.ErrDuplicatedKey
	}
	if err != nil {
		return nil, err
	}
	return group, nil
}

func (s *deviceGroupStore) Update(ctx context.Context, group *models.DeviceGroup) (*models.DeviceGroup, error) {
	err := s.locked(ctx, func(tx *gorm.DB) error {
		if err := validateGroupParent(tx, group); err != nil {
			return err
		}
		result := tx.Table("device_groups").Where("id = ?", group.ID).Select("*").Updates(group)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return gorm.ErrRecordNotFound
		}
		return nil
	})
	if constraintError(err, "ORA-00001", groupUniqueConstraint) {
		return nil, gorm.ErrDuplicatedKey
	}
	if err != nil {
		return nil, err
	}
	return group, nil
}

func (s *deviceGroupStore) Delete(ctx context.Context, id string) error {
	return s.locked(ctx, func(tx *gorm.DB) error {
		result := tx.Table("device_groups").Where("id = ?", id).Delete(&models.DeviceGroup{})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return gorm.ErrRecordNotFound
		}
		return nil
	})
}
