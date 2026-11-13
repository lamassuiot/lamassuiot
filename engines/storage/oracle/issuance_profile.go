package oracle

import (
	"context"
	"regexp"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"gorm.io/gorm"
)

type issuanceProfileStore struct{ db *gorm.DB }

var _ storage.IssuanceProfileRepo = (*issuanceProfileStore)(nil)

var profileFields = map[string]struct{}{"id": {}, "name": {}}
var profilePK = regexp.MustCompile(`(?i)\([^)]*\blamassu_profile_pk\)`)

// Oracle stores empty strings as NULL. Preserve the cross-database empty-name
// behavior with a single space in the NOT NULL column and normalize it on read.
const emptyProfileName = " "

func (s *issuanceProfileStore) Count(ctx context.Context) (int, error) {
	var count int64
	if err := s.db.WithContext(ctx).Table("issuance_profiles").Count(&count).Error; err != nil {
		return -1, err
	}
	return int(count), nil
}

func (s *issuanceProfileStore) SelectAll(ctx context.Context, req storage.StorageListRequest[models.IssuanceProfile]) (string, error) {
	apply := req.ApplyFunc
	if apply != nil {
		req.ApplyFunc = func(profile models.IssuanceProfile) {
			profile.Name = normalizeProfileName(profile.Name)
			apply(profile)
		}
	}
	return listRows(s.db.WithContext(ctx).Table("issuance_profiles"), req, profileFields, profileFields, nil, nil, []string{"id"}, func(profile models.IssuanceProfile) []any { return []any{profile.ID} })
}

func (s *issuanceProfileStore) SelectByID(ctx context.Context, id string) (bool, *models.IssuanceProfile, error) {
	var profile models.IssuanceProfile
	tx := s.db.WithContext(ctx).Table("issuance_profiles").Where("id = ?", id).Limit(1).Find(&profile)
	if tx.Error != nil {
		return false, nil, tx.Error
	}
	if tx.RowsAffected == 0 {
		return false, nil, nil
	}
	profile.Name = normalizeProfileName(profile.Name)
	return true, &profile, nil
}

func (s *issuanceProfileStore) Insert(ctx context.Context, profile *models.IssuanceProfile) (*models.IssuanceProfile, error) {
	persisted := *profile
	persisted.Name = persistProfileName(persisted.Name)
	if err := s.db.WithContext(ctx).Table("issuance_profiles").Create(&persisted).Error; err != nil {
		if constraintError(err, "ORA-00001", profilePK) {
			return nil, gorm.ErrDuplicatedKey
		}
		return nil, err
	}
	return profile, nil
}

func (s *issuanceProfileStore) Update(ctx context.Context, profile *models.IssuanceProfile) (*models.IssuanceProfile, error) {
	persisted := *profile
	persisted.Name = persistProfileName(persisted.Name)
	tx := s.db.WithContext(ctx).Table("issuance_profiles").Where("id = ?", profile.ID).Select("*").Updates(&persisted)
	if tx.Error != nil {
		return nil, tx.Error
	}
	if tx.RowsAffected != 1 {
		return nil, gorm.ErrRecordNotFound
	}
	return profile, nil
}

func persistProfileName(name string) string {
	if name == "" {
		return emptyProfileName
	}
	return name
}

func normalizeProfileName(name string) string {
	if name == emptyProfileName {
		return ""
	}
	return name
}

func (s *issuanceProfileStore) Delete(ctx context.Context, id string) error {
	tx := s.db.WithContext(ctx).Table("issuance_profiles").Where("id = ?", id).Delete(&models.IssuanceProfile{})
	if tx.Error != nil {
		return tx.Error
	}
	if tx.RowsAffected != 1 {
		return gorm.ErrRecordNotFound
	}
	return nil
}
