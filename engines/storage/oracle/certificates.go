package oracle

import (
	"context"
	"errors"
	"regexp"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
	oracleerrors "github.com/oracle/go-oracledb/v26/oracle/errors"
	"gorm.io/gorm"
)

type certificateStore struct{ db *gorm.DB }

var _ storage.CertificatesRepo = (*certificateStore)(nil)

var certificateFilterFields = map[string]struct{}{
	"serial_number": {}, "subject_key_id": {}, "authority_key_id": {}, "metadata": {}, "status": {}, "certificate": {},
	"key_meta_type": {}, "key_meta_bits": {}, "key_meta_strength": {}, "subject_common_name": {}, "subject_organization": {},
	"subject_organization_unit": {}, "subject_country": {}, "subject_state": {}, "subject_locality": {},
	"issuer_common_name": {}, "issuer_organization": {}, "issuer_organization_unit": {}, "issuer_country": {}, "issuer_state": {}, "issuer_locality": {},
	"valid_from": {}, "valid_to": {}, "revocation_timestamp": {}, "revocation_reason": {}, "type": {}, "engine_id": {}, "key_id": {},
	"issuer_meta_serial_number": {}, "issuer_meta_id": {}, "issuer_meta_level": {}, "extensions_key_usage": {}, "extensions_extended_key_usage": {}, "has_private_key": {}, "is_ca": {},
}
var certificateSortFields = map[string]struct{}{
	"serial_number": {}, "subject_key_id": {}, "authority_key_id": {}, "status": {}, "key_meta_type": {}, "key_meta_bits": {}, "key_meta_strength": {},
	"subject_common_name": {}, "subject_organization": {}, "subject_organization_unit": {}, "subject_country": {}, "subject_state": {}, "subject_locality": {},
	"issuer_common_name": {}, "issuer_organization": {}, "issuer_organization_unit": {}, "issuer_country": {}, "issuer_state": {}, "issuer_locality": {},
	"valid_from": {}, "valid_to": {}, "revocation_timestamp": {}, "revocation_reason": {}, "type": {}, "engine_id": {}, "key_id": {},
	"issuer_meta_serial_number": {}, "issuer_meta_id": {}, "issuer_meta_level": {}, "has_private_key": {}, "is_ca": {},
}

func (s *certificateStore) read(ctx context.Context) *gorm.DB {
	return s.db.WithContext(ctx).Table("certificates_view certificates")
}

func (s *certificateStore) count(tx *gorm.DB, params *resources.QueryParameters) (int, error) {
	if params != nil {
		var err error
		tx, err = applyFilters(tx, params.Filters, certificateFilterFields)
		if err != nil {
			return -1, err
		}
	}
	var n int64
	if err := tx.Count(&n).Error; err != nil {
		return -1, err
	}
	return int(n), nil
}

func (s *certificateStore) Count(ctx context.Context) (int, error) { return s.count(s.read(ctx), nil) }
func (s *certificateStore) CountWithFilters(ctx context.Context, params *resources.QueryParameters) (int, error) {
	return s.count(s.read(ctx), params)
}
func (s *certificateStore) CountByCA(ctx context.Context, id string) (int, error) {
	return s.count(s.read(ctx).Where("issuer_meta_id = ?", id), nil)
}
func (s *certificateStore) CountByCAIDWithFilters(ctx context.Context, id string, params *resources.QueryParameters) (int, error) {
	return s.count(s.read(ctx).Where("issuer_meta_id = ?", id), params)
}
func (s *certificateStore) CountByCAIDAndStatus(ctx context.Context, id string, status models.CertificateStatus) (int, error) {
	return s.count(s.read(ctx).Where("issuer_meta_id = ? AND status = ?", id, status), nil)
}

func (s *certificateStore) list(tx *gorm.DB, req storage.StorageListRequest[models.Certificate]) (string, error) {
	return listRows(tx, req, certificateFilterFields, certificateSortFields, nil, nil, []string{"serial_number"}, func(cert models.Certificate) []any { return []any{cert.SerialNumber} })
}
func (s *certificateStore) SelectAll(ctx context.Context, req storage.StorageListRequest[models.Certificate]) (string, error) {
	return s.list(s.read(ctx), req)
}
func (s *certificateStore) SelectByType(ctx context.Context, typ models.CertificateType, req storage.StorageListRequest[models.Certificate]) (string, error) {
	return s.list(s.read(ctx).Where(`"TYPE" = ?`, typ), req)
}
func (s *certificateStore) SelectByCA(ctx context.Context, id string, req storage.StorageListRequest[models.Certificate]) (string, error) {
	return s.list(s.read(ctx).Where("issuer_meta_id = ?", id), req)
}
func (s *certificateStore) SelectByCAIDAndStatus(ctx context.Context, id string, status models.CertificateStatus, req storage.StorageListRequest[models.Certificate]) (string, error) {
	return s.list(s.read(ctx).Where("issuer_meta_id = ? AND status = ?", id, status), req)
}
func (s *certificateStore) SelectByStatus(ctx context.Context, status models.CertificateStatus, req storage.StorageListRequest[models.Certificate]) (string, error) {
	return s.list(s.read(ctx).Where("status = ?", status), req)
}
func (s *certificateStore) SelectByExpirationDate(ctx context.Context, before, after time.Time, req storage.StorageListRequest[models.Certificate]) (string, error) {
	return s.list(s.read(ctx).Where("valid_to > ? AND valid_to < ? AND status <> ? AND status <> ?", after, before, models.StatusExpired, models.StatusRevoked), req)
}

var certificatePK = regexp.MustCompile(`(?i)\([^)]*\blamassu_cert_pk\)`)
var vaSignerConstraint = regexp.MustCompile(`(?i)\([^)]*\blamassu_va_signer_fk\)`)

func constraintError(err error, code string, constraint *regexp.Regexp) bool {
	var sqlErr oracleerrors.SQLError
	return errors.As(err, &sqlErr) && sqlErr.ErrorCode() == code && constraint.MatchString(sqlErr.Error())
}

func (s *certificateStore) SelectExistsBySerialNumber(ctx context.Context, serial string) (bool, *models.Certificate, error) {
	var cert models.Certificate
	tx := s.read(ctx).Where("certificates.serial_number = ?", serial).Limit(1).Find(&cert)
	if tx.Error != nil {
		return false, nil, tx.Error
	}
	if tx.RowsAffected == 0 {
		return false, nil, nil
	}
	return true, &cert, nil
}

func (s *certificateStore) reload(ctx context.Context, cert *models.Certificate) (*models.Certificate, error) {
	found, stored, err := s.SelectExistsBySerialNumber(ctx, cert.SerialNumber)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, gorm.ErrRecordNotFound
	}
	*cert = *stored
	return cert, nil
}

func (s *certificateStore) Insert(ctx context.Context, cert *models.Certificate) (*models.Certificate, error) {
	err := s.db.WithContext(ctx).Table("certificates").Create(cert).Error
	switch {
	case constraintError(err, "ORA-02291", certKeyConstraint):
		return nil, errs.ErrKeyNotFound
	case constraintError(err, "ORA-00001", certificatePK):
		return nil, errs.ErrCertificateAlreadyExists
	case err != nil:
		return nil, err
	}
	return s.reload(ctx, cert)
}

func (s *certificateStore) Update(ctx context.Context, cert *models.Certificate) (*models.Certificate, error) {
	tx := s.db.WithContext(ctx).Table("certificates").Where("serial_number = ?", cert.SerialNumber).Select("*").Updates(cert)
	if tx.Error != nil {
		return nil, tx.Error
	}
	if tx.RowsAffected != 1 {
		return nil, gorm.ErrRecordNotFound
	}
	return s.reload(ctx, cert)
}

func (s *certificateStore) Delete(ctx context.Context, serial string) error {
	tx := s.db.WithContext(ctx).Table("certificates").Where("serial_number = ?", serial).Delete(&models.Certificate{})
	if constraintError(tx.Error, "ORA-02292", vaSignerConstraint) {
		return errs.ErrCertificateInUse
	}
	if tx.Error != nil {
		return tx.Error
	}
	if tx.RowsAffected != 1 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

func (s *certificateStore) ReleaseKey(ctx context.Context, serials []string) error {
	if len(serials) == 0 {
		return nil
	}
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Avoid Oracle's IN-list limit while preserving all-or-nothing updates.
		for start := 0; start < len(serials); start += 1000 {
			end := min(start+1000, len(serials))
			if err := tx.Table("certificates").Where("serial_number IN ?", serials[start:end]).Update("key_id", nil).Error; err != nil {
				return err
			}
		}
		return nil
	})
}
