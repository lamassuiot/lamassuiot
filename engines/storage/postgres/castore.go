package postgres

import (
	"context"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

const caDBName = "ca_certificates"
const caJoinCaCertificatesAndCertificates = "JOIN certificates ON ca_certificates.serial_number = certificates.serial_number"

type PostgresCAStore struct {
	db      *gorm.DB
	querier *postgresDBQuerier[models.CACertificate]
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
	return db.querier.Count(ctx, []gormExtraOps{})
}

func (db *PostgresCAStore) CountByEngine(ctx context.Context, engineID string) (int, error) {
	return db.querier.Count(ctx, []gormExtraOps{
		{query: "certificates.engine_id = ? ", additionalWhere: []any{engineID}, joins: []string{caJoinCaCertificatesAndCertificates}},
	})
}

func (db *PostgresCAStore) CountByStatus(ctx context.Context, status models.CertificateStatus) (int, error) {
	return db.querier.Count(ctx, []gormExtraOps{
		{query: "certificates.status = ? ", additionalWhere: []any{status}, joins: []string{caJoinCaCertificatesAndCertificates}},
	})
}

func (db *PostgresCAStore) SelectByType(ctx context.Context, CAType models.CertificateType, req storage.StorageListRequest[models.CACertificate]) (string, error) {
	opts := []gormExtraOps{
		{query: "certificates.type = ? ", additionalWhere: []any{CAType}, joins: []string{caJoinCaCertificatesAndCertificates}},
	}
	return db.querier.SelectAll(ctx, req.QueryParams, opts, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *PostgresCAStore) SelectAll(ctx context.Context, req storage.StorageListRequest[models.CACertificate]) (string, error) {
	opts := []gormExtraOps{
		{joins: []string{caJoinCaCertificatesAndCertificates}},
	}
	// if req.QueryParams != nil {
	// 	for _, filter := range req.QueryParams.Filters {
	// 		if filter.Field == "subject.common_name" {
	// 			opts = []gormExtraOps{
	// 				{joins: []string{caJoinCaCertificatesAndCertificates}},
	// 			}
	// 			break
	// 		}
	// 	}
	// }

	return db.querier.SelectAll(ctx, req.QueryParams, opts, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *PostgresCAStore) SelectByCommonName(ctx context.Context, commonName string, req storage.StorageListRequest[models.CACertificate]) (string, error) {
	return db.querier.SelectAll(ctx, req.QueryParams, []gormExtraOps{
		{query: "certificates.subject_common_name = ? ", additionalWhere: []any{commonName}, joins: []string{caJoinCaCertificatesAndCertificates}},
	}, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *PostgresCAStore) SelectExistsBySerialNumber(ctx context.Context, serialNumber string) (bool, *models.CACertificate, error) {
	queryCol := "serial_number"
	return db.querier.SelectExists(ctx, serialNumber, &queryCol)
}

func (db *PostgresCAStore) SelectByParentCA(ctx context.Context, parentCAID string, req storage.StorageListRequest[models.CACertificate]) (string, error) {
	return db.querier.SelectAll(ctx, req.QueryParams, []gormExtraOps{
		{query: "certificates.issuer_meta_id = ? AND id != ?", additionalWhere: []any{parentCAID, parentCAID}, joins: []string{caJoinCaCertificatesAndCertificates}},
	}, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *PostgresCAStore) SelectBySubjectAndSubjectKeyID(ctx context.Context, sub models.Subject, skid string, req storage.StorageListRequest[models.CACertificate]) (string, error) {
	return db.querier.SelectAll(ctx, req.QueryParams, []gormExtraOps{
		{
			query: "certificates.subject_common_name = ? AND " +
				"certificates.subject_organization = ? AND " +
				"certificates.subject_organization_unit = ? AND " +
				"certificates.subject_country = ? AND " +
				"certificates.subject_state = ? AND " +
				"certificates.subject_locality = ? AND " +
				"subject_key_id = ?",
			additionalWhere: []any{sub.CommonName,
				sub.Organization,
				sub.OrganizationUnit,
				sub.Country,
				sub.State,
				sub.Locality,
				skid},
			joins: []string{caJoinCaCertificatesAndCertificates},
		},
	}, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *PostgresCAStore) SelectByIssuerAndAuthorityKeyID(ctx context.Context, iss models.Subject, akid string, req storage.StorageListRequest[models.CACertificate]) (string, error) {
	return db.querier.SelectAll(ctx, req.QueryParams, []gormExtraOps{
		{
			query: "certificates.issuer_common_name = ? AND " +
				"certificates.issuer_organization = ? AND " +
				"certificates.issuer_organization_unit = ? AND " +
				"certificates.issuer_country = ? AND " +
				"certificates.issuer_state = ? AND " +
				"certificates.issuer_locality = ? AND " +
				"authority_key_id = ?",
			additionalWhere: []any{iss.CommonName,
				iss.Organization,
				iss.OrganizationUnit,
				iss.Country,
				iss.State,
				iss.Locality,
				akid},
			joins: []string{caJoinCaCertificatesAndCertificates},
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
