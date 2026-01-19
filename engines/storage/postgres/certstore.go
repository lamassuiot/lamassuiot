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
	querier, err := TableQuery(logger, db, "certificates", []string{"serial_number"}, models.Certificate{})
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

func (db *PostgresCertificateStorage) SelectExistsBySerialNumber(ctx context.Context, id string) (bool, *models.Certificate, error) {
	return db.querier.SelectExists(ctx, map[string]string{"serial_number": id})
}

func (db *PostgresCertificateStorage) Insert(ctx context.Context, certificate *models.Certificate) (*models.Certificate, error) {
	return db.querier.Insert(ctx, certificate)
}

func (db *PostgresCertificateStorage) Update(ctx context.Context, certificate *models.Certificate) (*models.Certificate, error) {
	return db.querier.Update(ctx, certificate, map[string]string{"serial_number": certificate.SerialNumber})
}

func (db *PostgresCertificateStorage) Delete(ctx context.Context, serialNumber string) error {
	return db.querier.Delete(ctx, map[string]string{"serial_number": serialNumber})
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
