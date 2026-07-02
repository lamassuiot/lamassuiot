package postgres

import (
	"context"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

const caDBName = "ca_certificates"
const caJoinCaCertificatesAndCertificates = "JOIN certificates ON ca_certificates.serial_number = certificates.serial_number"

type PostgresCAStore struct {
	db      *gorm.DB
	querier *DBQuerier[models.CACertificate]
}

func NewCAPostgresRepository(log *logrus.Entry, db *gorm.DB) (storage.CACertificatesRepo, error) {
	querier, err := TableQuery(log, db, caDBName, "id", models.CACertificate{})
	if err != nil {
		return nil, err
	}

	return &PostgresCAStore{
		db:      db,
		querier: querier,
	}, nil
}

func (db *PostgresCAStore) Count(ctx context.Context) (int, error) {
	return db.querier.Count(ctx, []GormExtraOps{})
}

func (db *PostgresCAStore) CountWithFilters(ctx context.Context, queryParams *resources.QueryParameters) (int, error) {
	if queryParams == nil {
		return db.Count(ctx)
	}

	opts := []GormExtraOps{
		{Joins: []string{caJoinCaCertificatesAndCertificates}},
	}
	return db.querier.CountFiltered(ctx, queryParams.Filters, opts)
}

func (db *PostgresCAStore) CountByEngine(ctx context.Context, engineID string) (int, error) {
	return db.querier.Count(ctx, []GormExtraOps{
		{Query: "certificates.engine_id = ? ", AdditionalWhere: []any{engineID}, Joins: []string{caJoinCaCertificatesAndCertificates}},
	})
}

func (db *PostgresCAStore) CountByEngineWithFilters(ctx context.Context, engineID string, queryParams *resources.QueryParameters) (int, error) {
	opts := []GormExtraOps{
		{Query: "certificates.engine_id = ? ", AdditionalWhere: []any{engineID}, Joins: []string{caJoinCaCertificatesAndCertificates}},
	}

	if queryParams == nil {
		return db.querier.Count(ctx, opts)
	}

	return db.querier.CountFiltered(ctx, queryParams.Filters, opts)
}

func (db *PostgresCAStore) CountByStatus(ctx context.Context, status models.CertificateStatus) (int, error) {
	return db.querier.Count(ctx, []GormExtraOps{
		{Query: "certificates.status = ? ", AdditionalWhere: []any{status}, Joins: []string{caJoinCaCertificatesAndCertificates}},
	})
}

func (db *PostgresCAStore) SelectByType(ctx context.Context, CAType models.CertificateType, req storage.StorageListRequest[models.CACertificate]) (string, error) {
	opts := []GormExtraOps{
		{Query: "certificates.type = ? ", AdditionalWhere: []any{CAType}, Joins: []string{caJoinCaCertificatesAndCertificates}},
	}
	return db.querier.SelectAll(ctx, req.QueryParams, opts, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *PostgresCAStore) SelectAll(ctx context.Context, req storage.StorageListRequest[models.CACertificate]) (string, error) {
	opts := []GormExtraOps{
		{Joins: []string{caJoinCaCertificatesAndCertificates}},
	}
	// if req.QueryParams != nil {
	// 	for _, filter := range req.QueryParams.Filters {
	// 		if filter.Field == "subject.common_name" {
	// 			opts = []GormExtraOps{
	// 				{Joins: []string{caJoinCaCertificatesAndCertificates}},
	// 			}
	// 			break
	// 		}
	// 	}
	// }

	return db.querier.SelectAll(ctx, req.QueryParams, opts, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *PostgresCAStore) SelectByCommonName(ctx context.Context, commonName string, req storage.StorageListRequest[models.CACertificate]) (string, error) {
	return db.querier.SelectAll(ctx, req.QueryParams, []GormExtraOps{
		{Query: "certificates.subject_common_name = ? ", AdditionalWhere: []any{commonName}, Joins: []string{caJoinCaCertificatesAndCertificates}},
	}, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *PostgresCAStore) SelectExistsBySerialNumber(ctx context.Context, serialNumber string) (bool, *models.CACertificate, error) {
	queryCol := "serial_number"
	return db.querier.SelectExists(ctx, serialNumber, &queryCol)
}

func (db *PostgresCAStore) SelectByParentCA(ctx context.Context, parentCAID string, req storage.StorageListRequest[models.CACertificate]) (string, error) {
	return db.querier.SelectAll(ctx, req.QueryParams, []GormExtraOps{
		{Query: "certificates.issuer_meta_id = ? AND id != ?", AdditionalWhere: []any{parentCAID, parentCAID}, Joins: []string{caJoinCaCertificatesAndCertificates}},
	}, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *PostgresCAStore) SelectBySubjectAndSubjectKeyID(ctx context.Context, sub models.Subject, skid string, req storage.StorageListRequest[models.CACertificate]) (string, error) {
	return db.querier.SelectAll(ctx, req.QueryParams, []GormExtraOps{
		{
			Query: "certificates.subject_common_name = ? AND " +
				"certificates.subject_organization = ? AND " +
				"certificates.subject_organization_unit = ? AND " +
				"certificates.subject_country = ? AND " +
				"certificates.subject_state = ? AND " +
				"certificates.subject_locality = ? AND " +
				"subject_key_id = ?",
			AdditionalWhere: []any{sub.CommonName,
				sub.Organization,
				sub.OrganizationUnit,
				sub.Country,
				sub.State,
				sub.Locality,
				skid},
			Joins: []string{caJoinCaCertificatesAndCertificates},
		},
	}, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *PostgresCAStore) SelectByIssuerAndAuthorityKeyID(ctx context.Context, iss models.Subject, akid string, req storage.StorageListRequest[models.CACertificate]) (string, error) {
	return db.querier.SelectAll(ctx, req.QueryParams, []GormExtraOps{
		{
			Query: "certificates.issuer_common_name = ? AND " +
				"certificates.issuer_organization = ? AND " +
				"certificates.issuer_organization_unit = ? AND " +
				"certificates.issuer_country = ? AND " +
				"certificates.issuer_state = ? AND " +
				"certificates.issuer_locality = ? AND " +
				"authority_key_id = ?",
			AdditionalWhere: []any{iss.CommonName,
				iss.Organization,
				iss.OrganizationUnit,
				iss.Country,
				iss.State,
				iss.Locality,
				akid},
			Joins: []string{caJoinCaCertificatesAndCertificates},
		},
	}, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *PostgresCAStore) SelectExistsByID(ctx context.Context, id string) (bool, *models.CACertificate, error) {
	return db.querier.SelectExists(ctx, id, nil)
}

func (db *PostgresCAStore) Insert(ctx context.Context, caCertificate *models.CACertificate) (*models.CACertificate, error) {
	return db.querier.Insert(ctx, caCertificate, caCertificate.ID)
}

func (db *PostgresCAStore) Update(ctx context.Context, caCertificate *models.CACertificate) (*models.CACertificate, error) {
	return db.querier.Update(ctx, caCertificate, caCertificate.ID)
}

func (db *PostgresCAStore) Delete(ctx context.Context, id string) error {
	return db.querier.Delete(ctx, id)
}
