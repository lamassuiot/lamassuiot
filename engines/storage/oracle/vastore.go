package oracle

import (
	"context"
	"regexp"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"gorm.io/gorm"
)

type vaStore struct{ db *gorm.DB }

var _ storage.VARepo = (*vaStore)(nil)
var vaPK = regexp.MustCompile(`(?i)\([^)]*\blamassu_va_pk\)`)
var vaFields = map[string]struct{}{
	"ca_ski": {}, "crl_refresh_interval": {}, "crl_validity": {}, "crl_signer_certificate_serial_number": {},
	"crl_regenerate_on_revoke": {}, "latest_crl_valid_from": {}, "latest_crl_valid_until": {},
}

func (s *vaStore) Get(ctx context.Context, id string) (bool, *models.VARole, error) {
	var role models.VARole
	tx := s.db.WithContext(ctx).Table("va_role").Where("ca_ski = ?", id).Limit(1).Find(&role)
	if tx.Error != nil {
		return false, nil, tx.Error
	}
	if tx.RowsAffected == 0 {
		return false, nil, nil
	}
	return true, &role, nil
}

func (s *vaStore) GetAll(ctx context.Context, req storage.StorageListRequest[models.VARole]) (string, error) {
	return listRows(s.db.WithContext(ctx).Table("va_role"), req, vaFields, vaFields, nil, nil, []string{"ca_ski"}, func(role models.VARole) []any { return []any{role.CASubjectKeyID} })
}

func vaWriteError(err error) error {
	if constraintError(err, "ORA-02291", vaSignerConstraint) {
		return errs.ErrCertificateNotFound
	}
	if constraintError(err, "ORA-00001", vaPK) {
		return gorm.ErrDuplicatedKey
	}
	return err
}

func (s *vaStore) Insert(ctx context.Context, role *models.VARole) (*models.VARole, error) {
	if err := s.db.WithContext(ctx).Table("va_role").Create(role).Error; err != nil {
		return nil, vaWriteError(err)
	}
	return role, nil
}

func (s *vaStore) Update(ctx context.Context, role *models.VARole) (*models.VARole, error) {
	tx := s.db.WithContext(ctx).Table("va_role").Where("ca_ski = ?", role.CASubjectKeyID).Select("*").Updates(role)
	if tx.Error != nil {
		return nil, vaWriteError(tx.Error)
	}
	if tx.RowsAffected != 1 {
		return nil, gorm.ErrRecordNotFound
	}
	return role, nil
}
