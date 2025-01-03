package postgres

import (
	"context"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

const caDBName = "ca_certificates"

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
		{query: "certificates.engine_id = ? ", additionalWhere: []any{engineID}, joins: []string{"JOIN certificates ON ca_certificates.serial_number = certificates.serial_number"}},
	})
}

func (db *PostgresCAStore) CountByStatus(ctx context.Context, status models.CertificateStatus) (int, error) {
	return db.querier.Count(ctx, []gormExtraOps{
		{query: "certificates.status = ? ", additionalWhere: []any{status}, joins: []string{"JOIN certificates ON ca_certificates.serial_number = certificates.serial_number"}},
	})
}

func (db *PostgresCAStore) SelectByType(ctx context.Context, CAType models.CertificateType, req storage.StorageListRequest[models.CACertificate]) (string, error) {
	opts := []gormExtraOps{
		{query: "certificates.type = ? ", additionalWhere: []any{CAType}, joins: []string{"JOIN certificates ON ca_certificates.serial_number = certificates.serial_number"}},
	}
	return db.querier.SelectAll(ctx, req.QueryParams, opts, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *PostgresCAStore) SelectAll(ctx context.Context, req storage.StorageListRequest[models.CACertificate]) (string, error) {
	return db.querier.SelectAll(ctx, req.QueryParams, []gormExtraOps{}, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *PostgresCAStore) SelectByCommonName(ctx context.Context, commonName string, req storage.StorageListRequest[models.CACertificate]) (string, error) {
	return db.querier.SelectAll(ctx, req.QueryParams, []gormExtraOps{
		{query: "certificates.subject_common_name = ? ", additionalWhere: []any{commonName}, joins: []string{"JOIN certificates ON ca_certificates.serial_number = certificates.serial_number"}},
	}, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *PostgresCAStore) SelectExistsBySerialNumber(ctx context.Context, serialNumber string) (bool, *models.CACertificate, error) {
	queryCol := "serial_number"
	return db.querier.SelectExists(ctx, serialNumber, &queryCol)
}

func (db *PostgresCAStore) SelectByParentCA(ctx context.Context, parentCAID string, req storage.StorageListRequest[models.CACertificate]) (string, error) {
	return db.querier.SelectAll(ctx, req.QueryParams, []gormExtraOps{
		{query: "certificates.issuer_meta_id = ? AND id != ?", additionalWhere: []any{parentCAID, parentCAID}, joins: []string{"JOIN certificates ON ca_certificates.serial_number = certificates.serial_number"}},
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