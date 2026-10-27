package postgres

import (
	"context"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type PostgresCertificateStorage struct {
	db      *gorm.DB
	querier *DBQuerier[models.Certificate]
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
	return db.querier.Count(ctx, []GormExtraOps{})
}

func (db *PostgresCertificateStorage) CountWithFilters(ctx context.Context, queryParams *resources.QueryParameters) (int, error) {
	if queryParams == nil {
		return db.Count(ctx)
	}

	return db.querier.CountFiltered(ctx, queryParams.Filters, []GormExtraOps{})
}

func (db *PostgresCertificateStorage) CountByCAIDWithFilters(ctx context.Context, caID string, queryParams *resources.QueryParameters) (int, error) {
	opts := []GormExtraOps{
		{Query: "issuer_meta_id = ?", AdditionalWhere: []any{caID}},
	}

	if queryParams == nil {
		return db.querier.Count(ctx, opts)
	}

	return db.querier.CountFiltered(ctx, queryParams.Filters, opts)
}

func (db *PostgresCertificateStorage) CountByCAIDAndStatus(ctx context.Context, caID string, status models.CertificateStatus) (int, error) {
	opts := []GormExtraOps{
		{Query: "issuer_meta_id = ?", AdditionalWhere: []any{caID}},
		{Query: "status = ?", AdditionalWhere: []any{status}},
	}
	return db.querier.Count(ctx, opts)
}

func (db *PostgresCertificateStorage) SelectByType(ctx context.Context, CAType models.CertificateType, req storage.StorageListRequest[models.Certificate]) (string, error) {
	opts := []GormExtraOps{
		{Query: "type = ?", AdditionalWhere: []any{CAType}},
	}
	return db.querier.SelectAll(ctx, req.QueryParams, opts, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *PostgresCertificateStorage) SelectAll(ctx context.Context, req storage.StorageListRequest[models.Certificate]) (string, error) {
	return db.querier.SelectAll(ctx, req.QueryParams, []GormExtraOps{}, req.ExhaustiveRun, req.ApplyFunc)
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

func (db *PostgresCertificateStorage) Delete(ctx context.Context, serialNumber string) error {
	return db.querier.Delete(ctx, serialNumber)
}

func (db *PostgresCertificateStorage) SelectByCA(ctx context.Context, caID string, req storage.StorageListRequest[models.Certificate]) (string, error) {
	opts := []GormExtraOps{
		{Query: "issuer_meta_id = ?", AdditionalWhere: []any{caID}},
	}
	return db.querier.SelectAll(ctx, req.QueryParams, opts, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *PostgresCertificateStorage) SelectByExpirationDate(ctx context.Context, beforeExpirationDate time.Time, afterExpirationDate time.Time, req storage.StorageListRequest[models.Certificate]) (string, error) {
	opts := []GormExtraOps{
		{Query: "valid_to > ?", AdditionalWhere: []any{afterExpirationDate}},
		{Query: "valid_to < ?", AdditionalWhere: []any{beforeExpirationDate}},
		{Query: "status != ?", AdditionalWhere: []any{models.StatusExpired}},
		{Query: "status != ?", AdditionalWhere: []any{models.StatusRevoked}},
	}

	return db.querier.SelectAll(ctx, req.QueryParams, opts, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *PostgresCertificateStorage) SelectByCAIDAndStatus(ctx context.Context, CAID string, status models.CertificateStatus, req storage.StorageListRequest[models.Certificate]) (string, error) {
	opts := []GormExtraOps{
		{Query: "status = ?", AdditionalWhere: []any{status}},
		{Query: "issuer_meta_id = ?", AdditionalWhere: []any{CAID}},
	}

	return db.querier.SelectAll(ctx, req.QueryParams, opts, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *PostgresCertificateStorage) SelectByStatus(ctx context.Context, status models.CertificateStatus, req storage.StorageListRequest[models.Certificate]) (string, error) {
	opts := []GormExtraOps{
		{Query: "status = ?", AdditionalWhere: []any{status}},
	}

	return db.querier.SelectAll(ctx, req.QueryParams, opts, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *PostgresCertificateStorage) CountByCA(ctx context.Context, CAID string) (int, error) {
	return db.querier.Count(ctx, []GormExtraOps{
		{Query: "issuer_meta_id = ?", AdditionalWhere: []any{CAID}},
	})
}

func (db *PostgresCertificateStorage) SelectKeyUsersAfter(ctx context.Context, after string, limit int) ([]models.CertificateKeyRef, error) {
	refs := []models.CertificateKeyRef{}
	// A CA certificate keeps its key in use only while it is the current certificate of a CA:
	// reissued and deleted CAs leave their certificates behind. Paging uses byte order, like the
	// KMS reconciliation ranges.
	tx := db.db.WithContext(ctx).Raw(`
		SELECT c.serial_number, c.key_id, c.engine_id
		FROM certificates AS c
		WHERE c.key_id <> '' AND c.engine_id <> '' AND c.serial_number COLLATE "C" > ?
		  AND (c.is_ca = false OR EXISTS (SELECT 1 FROM ca_certificates AS ca WHERE ca.serial_number = c.serial_number))
		ORDER BY c.serial_number COLLATE "C"
		LIMIT ?`, after, limit).Scan(&refs)
	return refs, tx.Error
}
