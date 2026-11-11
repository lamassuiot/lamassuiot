package oracle

import (
	"context"
	"regexp"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type caStore struct{ db *gorm.DB }

var _ storage.CACertificatesRepo = (*caStore)(nil)

var caPK = regexp.MustCompile(`(?i)\([^)]*\blamassu_ca_(?:pk|id_unique)\)`)

// CA fields live in ca_certificates; most filterable certificate fields come
// from the joined view. Ambiguous fields keep the CA table's meaning.
var caFilterFields, caSortFields, caFieldTables = caFields()

func caFields() (map[string]struct{}, map[string]struct{}, map[string]string) {
	filters, sorts, tables := map[string]struct{}{}, map[string]struct{}{}, map[string]string{}
	for name := range certificateFilterFields {
		filters[name] = struct{}{}
		tables[name] = "certificates"
	}
	for name := range certificateSortFields {
		sorts[name] = struct{}{}
	}
	for _, name := range []string{"id", "serial_number", "profile_id", "metadata", "creation_ts", "level"} {
		filters[name] = struct{}{}
		delete(tables, name)
		if name != "metadata" {
			sorts[name] = struct{}{}
		}
	}
	return filters, sorts, tables
}

func (s *caStore) read(ctx context.Context) *gorm.DB {
	return s.db.WithContext(ctx).Table("ca_certificates").Select("ca_certificates.*").
		Joins("JOIN certificates_view certificates ON ca_certificates.serial_number = certificates.serial_number")
}

func preloadCACertificate(tx *gorm.DB) *gorm.DB {
	return tx.Preload("Certificate", func(association *gorm.DB) *gorm.DB { return association.Table("certificates_view certificates") })
}

func (s *caStore) count(tx *gorm.DB, params *resources.QueryParameters) (int, error) {
	if params != nil {
		var err error
		tx, err = applyFiltersOn(tx, params.Filters, caFilterFields, caFieldTables)
		if err != nil {
			return -1, err
		}
	}
	var n int64
	if err := tx.Select("COUNT(*)").Count(&n).Error; err != nil {
		return -1, err
	}
	return int(n), nil
}

func (s *caStore) Count(ctx context.Context) (int, error) { return s.count(s.read(ctx), nil) }
func (s *caStore) CountWithFilters(ctx context.Context, params *resources.QueryParameters) (int, error) {
	return s.count(s.read(ctx), params)
}
func (s *caStore) CountByEngine(ctx context.Context, id string) (int, error) {
	return s.count(s.read(ctx).Where("certificates.engine_id = ?", id), nil)
}
func (s *caStore) CountByEngineWithFilters(ctx context.Context, id string, params *resources.QueryParameters) (int, error) {
	return s.count(s.read(ctx).Where("certificates.engine_id = ?", id), params)
}
func (s *caStore) CountByStatus(ctx context.Context, status models.CertificateStatus) (int, error) {
	return s.count(s.read(ctx).Where("certificates.status = ?", status), nil)
}

func (s *caStore) list(tx *gorm.DB, req storage.StorageListRequest[models.CACertificate]) (string, error) {
	return listRows(preloadCACertificate(tx), req, caFilterFields, caSortFields, caFieldTables, nil, []string{"id"}, func(ca models.CACertificate) []any { return []any{ca.ID} })
}
func (s *caStore) SelectAll(ctx context.Context, req storage.StorageListRequest[models.CACertificate]) (string, error) {
	return s.list(s.read(ctx), req)
}
func (s *caStore) SelectByType(ctx context.Context, typ models.CertificateType, req storage.StorageListRequest[models.CACertificate]) (string, error) {
	return s.list(s.read(ctx).Where(`certificates."TYPE" = ?`, typ), req)
}
func (s *caStore) SelectByCommonName(ctx context.Context, name string, req storage.StorageListRequest[models.CACertificate]) (string, error) {
	return s.list(subjectEquals(s.read(ctx), "subject_common_name", name), req)
}
func (s *caStore) SelectByParentCA(ctx context.Context, id string, req storage.StorageListRequest[models.CACertificate]) (string, error) {
	return s.list(s.read(ctx).Where("certificates.issuer_meta_id = ? AND ca_certificates.id <> ?", id, id), req)
}

// Oracle represents empty SQL strings as NULL, including empty X.509 subject
// components. Use IS NULL to preserve equality for these fields.
func subjectEquals(tx *gorm.DB, name, value string) *gorm.DB {
	var v any = value
	if value == "" {
		v = nil
	}
	return tx.Where(clause.Eq{Column: clause.Column{Table: "certificates", Name: name}, Value: v})
}

func (s *caStore) selectBySubject(ctx context.Context, subject models.Subject, keyID, prefix, keyColumn string, req storage.StorageListRequest[models.CACertificate]) (string, error) {
	tx := s.read(ctx)
	for _, part := range []struct{ name, value string }{
		{"common_name", subject.CommonName}, {"organization", subject.Organization}, {"organization_unit", subject.OrganizationUnit},
		{"country", subject.Country}, {"state", subject.State}, {"locality", subject.Locality},
	} {
		tx = subjectEquals(tx, prefix+part.name, part.value)
	}
	return s.list(subjectEquals(tx, keyColumn, keyID), req)
}
func (s *caStore) SelectBySubjectAndSubjectKeyID(ctx context.Context, subject models.Subject, id string, req storage.StorageListRequest[models.CACertificate]) (string, error) {
	return s.selectBySubject(ctx, subject, id, "subject_", "subject_key_id", req)
}
func (s *caStore) SelectByIssuerAndAuthorityKeyID(ctx context.Context, subject models.Subject, id string, req storage.StorageListRequest[models.CACertificate]) (string, error) {
	return s.selectBySubject(ctx, subject, id, "issuer_", "authority_key_id", req)
}

func (s *caStore) selectOne(tx *gorm.DB) (bool, *models.CACertificate, error) {
	var ca models.CACertificate
	tx = preloadCACertificate(tx).Limit(1).Find(&ca)
	if tx.Error != nil {
		return false, nil, tx.Error
	}
	if tx.RowsAffected == 0 {
		return false, nil, nil
	}
	return true, &ca, nil
}
func (s *caStore) SelectExistsByID(ctx context.Context, id string) (bool, *models.CACertificate, error) {
	return s.selectOne(s.read(ctx).Where("ca_certificates.id = ?", id))
}
func (s *caStore) SelectExistsBySerialNumber(ctx context.Context, serial string) (bool, *models.CACertificate, error) {
	return s.selectOne(s.read(ctx).Where("ca_certificates.serial_number = ?", serial))
}

func (s *caStore) reload(ctx context.Context, ca *models.CACertificate) (*models.CACertificate, error) {
	found, stored, err := s.SelectExistsByID(ctx, ca.ID)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, gorm.ErrRecordNotFound
	}
	*ca = *stored
	return ca, nil
}
func (s *caStore) Insert(ctx context.Context, ca *models.CACertificate) (*models.CACertificate, error) {
	err := s.db.WithContext(ctx).Table("ca_certificates").Omit("Certificate").Create(ca).Error
	if constraintError(err, "ORA-00001", caPK) {
		return nil, errs.ErrCAAlreadyExists
	}
	if err != nil {
		return nil, err
	}
	return s.reload(ctx, ca)
}
func (s *caStore) Update(ctx context.Context, ca *models.CACertificate) (*models.CACertificate, error) {
	tx := s.db.WithContext(ctx).Table("ca_certificates").Where("id = ?", ca.ID).Omit("Certificate").Select("*").Updates(ca)
	if tx.Error != nil {
		return nil, tx.Error
	}
	if tx.RowsAffected != 1 {
		return nil, gorm.ErrRecordNotFound
	}
	return s.reload(ctx, ca)
}
func (s *caStore) Delete(ctx context.Context, id string) error {
	tx := s.db.WithContext(ctx).Table("ca_certificates").Where("id = ?", id).Delete(&models.CACertificate{})
	if tx.Error != nil {
		return tx.Error
	}
	if tx.RowsAffected != 1 {
		return gorm.ErrRecordNotFound
	}
	return nil
}
