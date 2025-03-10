package postgres

import (
	"context"
	"time"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type PostgresCertificateStorage struct {
	db      *gorm.DB
	querier *postgresDBQuerier[models.Certificate]
}

func NewCertificateRepository(logger *logrus.Entry, db *gorm.DB) (storage.CertificatesRepo, error) {
	querier, err := TableQuery(logger, db, "certificates", "serial_number", models.Certificate{})
	if err != nil {
		return nil, err
	}

	return &PostgresCertificateStorage{
		db:      db,
		querier: querier,
	}, nil
}

func (db *PostgresCertificateStorage) Count(ctx context.Context) (int, error) {
	return db.querier.Count(ctx, []gormExtraOps{})
}

func (db *PostgresCertificateStorage) CountByCAIDAndStatus(ctx context.Context, caID string, status models.CertificateStatus) (int, error) {
	opts := []gormExtraOps{
		{query: "issuer_meta_id = ?", additionalWhere: []any{caID}},
		{query: "status = ?", additionalWhere: []any{status}},
	}
	return db.querier.Count(ctx, opts)
}

func (db *PostgresCertificateStorage) SelectByType(ctx context.Context, CAType models.CertificateType, req storage.StorageListRequest[models.Certificate]) (string, error) {
	opts := []gormExtraOps{
		{query: "type = ?", additionalWhere: []any{CAType}},
	}
	return db.querier.SelectAll(ctx, req.QueryParams, opts, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *PostgresCertificateStorage) SelectAll(ctx context.Context, req storage.StorageListRequest[models.Certificate]) (string, error) {
	return db.querier.SelectAll(ctx, req.QueryParams, []gormExtraOps{}, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *PostgresCertificateStorage) SelectExistsCAByID(ctx context.Context, caID string) (bool, *models.Certificate, error) {
	queryColumn := "subject_key_id"
	exist, ca, err := db.querier.SelectExists(ctx, caID, &queryColumn)
	if ca != nil && !ca.IsCA {
		return false, nil, nil
	}
	return exist, ca, err
}

func (db *PostgresCertificateStorage) SelectExistsCABySerialNumber(ctx context.Context, serialNumber string) (bool, *models.Certificate, error) {
	exist, ca, err := db.querier.SelectExists(ctx, serialNumber, nil)
	if ca != nil && !ca.IsCA {
		return false, nil, nil
	}
	return exist, ca, err
}

func (db *PostgresCertificateStorage) SelectCAByParentCA(ctx context.Context, parentCAID string, req storage.StorageListRequest[models.Certificate]) (string, error) {
	return db.querier.SelectAll(ctx, req.QueryParams, []gormExtraOps{
		{query: "is_ca = ? AND issuer_meta_id = ? AND subject_key_id != ?", additionalWhere: []any{true, parentCAID, parentCAID}},
	}, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *PostgresCertificateStorage) SelectCAByCommonName(ctx context.Context, commonName string, req storage.StorageListRequest[models.Certificate]) (string, error) {
	return db.querier.SelectAll(ctx, req.QueryParams, []gormExtraOps{
		{query: "is_ca = ? AND subject_common_name = ?", additionalWhere: []any{true, commonName}},
	}, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *PostgresCertificateStorage) SelectAllCA(ctx context.Context, req storage.StorageListRequest[models.Certificate]) (string, error) {
	return db.querier.SelectAll(ctx, req.QueryParams, []gormExtraOps{
		{query: "is_ca = ?", additionalWhere: []any{true}},
	}, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *PostgresCertificateStorage) DeleteCA(ctx context.Context, id string) error {
	queryColumn := "subject_key_id"
	_, ca, err := db.querier.SelectExists(ctx, id, &queryColumn)
	if err != nil {
		return err
	}
	if ca == nil || !ca.IsCA {
		return gorm.ErrRecordNotFound
	}
	return db.querier.Delete(ctx, ca.SerialNumber)
}

func (db *PostgresCertificateStorage) CountCA(ctx context.Context) (int, error) {
	return db.querier.Count(ctx, []gormExtraOps{
		{query: "is_ca = ?", additionalWhere: []any{true}},
	})
}

func (db *PostgresCertificateStorage) CountCAByEngine(ctx context.Context, engineID string) (int, error) {
	return db.querier.Count(ctx, []gormExtraOps{
		{query: "is_ca = ? AND engine_id = ? ", additionalWhere: []any{true, engineID}},
	})
}

func (db *PostgresCertificateStorage) CountCAByStatus(ctx context.Context, status models.CertificateStatus) (int, error) {
	return db.querier.Count(ctx, []gormExtraOps{
		{query: "is_ca = ? AND certificates.status = ?", additionalWhere: []any{true, status}},
	})
}

func (db *PostgresCertificateStorage) SelectExistsBySerialNumber(ctx context.Context, id string) (bool, *models.Certificate, error) {
	return db.querier.SelectExists(ctx, id, nil)
}

func (db *PostgresCertificateStorage) Insert(ctx context.Context, certificate *models.Certificate) (*models.Certificate, error) {
	return db.querier.Insert(ctx, certificate, certificate.SerialNumber)
}

func (db *PostgresCertificateStorage) Update(ctx context.Context, certificate *models.Certificate) (*models.Certificate, error) {
	return db.querier.Update(ctx, certificate, certificate.SerialNumber)
}

func (db *PostgresCertificateStorage) SelectByCA(ctx context.Context, caID string, req storage.StorageListRequest[models.Certificate]) (string, error) {
	opts := []gormExtraOps{
		{query: "issuer_meta_id = ?", additionalWhere: []any{caID}},
	}
	return db.querier.SelectAll(ctx, req.QueryParams, opts, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *PostgresCertificateStorage) SelectByExpirationDate(ctx context.Context, beforeExpirationDate time.Time, afterExpirationDate time.Time, req storage.StorageListRequest[models.Certificate]) (string, error) {
	opts := []gormExtraOps{
		{query: "valid_to > ?", additionalWhere: []any{afterExpirationDate}},
		{query: "valid_to < ?", additionalWhere: []any{beforeExpirationDate}},
		{query: "status != ?", additionalWhere: []any{models.StatusExpired}},
		{query: "status != ?", additionalWhere: []any{models.StatusRevoked}},
	}

	return db.querier.SelectAll(ctx, req.QueryParams, opts, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *PostgresCertificateStorage) SelectByCAIDAndStatus(ctx context.Context, CAID string, status models.CertificateStatus, req storage.StorageListRequest[models.Certificate]) (string, error) {
	opts := []gormExtraOps{
		{query: "status = ?", additionalWhere: []any{status}},
		{query: "issuer_meta_id = ?", additionalWhere: []any{CAID}},
	}

	return db.querier.SelectAll(ctx, req.QueryParams, opts, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *PostgresCertificateStorage) SelectByStatus(ctx context.Context, status models.CertificateStatus, req storage.StorageListRequest[models.Certificate]) (string, error) {
	opts := []gormExtraOps{
		{query: "status = ?", additionalWhere: []any{status}},
	}

	return db.querier.SelectAll(ctx, req.QueryParams, opts, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *PostgresCertificateStorage) CountByCA(ctx context.Context, CAID string) (int, error) {
	return db.querier.Count(ctx, []gormExtraOps{
		{query: "issuer_meta_id = ?", additionalWhere: []any{CAID}},
	})
}

func (db *PostgresCertificateStorage) SelectCAByIssuerAndAuthorityKeyID(ctx context.Context, iss models.Subject, akid string, req storage.StorageListRequest[models.Certificate]) (string, error) {
	return db.querier.SelectAll(ctx, req.QueryParams, []gormExtraOps{
		{query: "is_ca = ? AND " +
			"issuer_common_name = ? AND " +
			"issuer_organization = ? AND " +
			"issuer_organization_unit = ? AND " +
			"issuer_country = ? AND " +
			"issuer_state = ? AND " +
			"issuer_locality = ? AND " +
			"authority_key_id = ?", additionalWhere: []any{true,
			iss.CommonName,
			iss.Organization,
			iss.OrganizationUnit,
			iss.Country,
			iss.State,
			iss.Locality,
			akid}},
	}, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *PostgresCertificateStorage) SelectCABySubjectAndSubjectKeyID(ctx context.Context, sub models.Subject, skid string, req storage.StorageListRequest[models.Certificate]) (string, error) {
	return db.querier.SelectAll(ctx, req.QueryParams, []gormExtraOps{
		{query: "is_ca = ? AND " +
			"subject_common_name = ? AND " +
			"subject_organization = ? AND " +
			"subject_organization_unit = ? AND " +
			"subject_country = ? AND " +
			"subject_state = ? AND " +
			"subject_locality = ? AND " +
			"subject_key_id = ?", additionalWhere: []any{true,
			sub.CommonName,
			sub.Organization,
			sub.OrganizationUnit,
			sub.Country,
			sub.State,
			sub.Locality,
			skid}},
	}, req.ExhaustiveRun, req.ApplyFunc)
}
