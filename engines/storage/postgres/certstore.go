package postgres

import (
	"context"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type PostgresCertificateStorage struct {
	db          *gorm.DB
	querier     *DBQuerier[models.Certificate]
	readQuerier *DBQuerier[models.Certificate]
}

// certificateKeyForeignKey is the constraint of the certificates table that references the KMS keys.
const certificateKeyForeignKey = "certificates_key_fk"

// Keep the canonical table alias so authorization filters still target certificate reads.
const certificateReadTable = "certificates_view AS certificates"

// isCertificateKeyViolation tells whether err is a certificate referencing a key the KMS does not hold.
// Other foreign keys, such as the one of a CA to its certificate, report as foreign-key violations too.
func isCertificateKeyViolation(err error) bool {
	return isForeignKeyViolation(err, certificateKeyForeignKey)
}

func NewCertificateRepository(logger *logrus.Entry, db *gorm.DB) (storage.CertificatesRepo, error) {
	querier, err := TableQuery(logger, db, "certificates", "serial_number", models.Certificate{})
	if err != nil {
		return nil, err
	}

	readQuerier, err := TableQuery(logger, db, certificateReadTable, "serial_number", models.Certificate{})
	if err != nil {
		return nil, err
	}

	return &PostgresCertificateStorage{
		db:          db,
		querier:     querier,
		readQuerier: readQuerier,
	}, nil
}

func (db *PostgresCertificateStorage) Count(ctx context.Context) (int, error) {
	return db.readQuerier.Count(ctx, []GormExtraOps{})
}

func (db *PostgresCertificateStorage) CountWithFilters(ctx context.Context, queryParams *resources.QueryParameters) (int, error) {
	if queryParams == nil {
		return db.Count(ctx)
	}

	return db.readQuerier.CountFiltered(ctx, queryParams.Filters, []GormExtraOps{})
}

func (db *PostgresCertificateStorage) CountByCAIDWithFilters(ctx context.Context, caID string, queryParams *resources.QueryParameters) (int, error) {
	opts := []GormExtraOps{
		{Query: "issuer_meta_id = ?", AdditionalWhere: []any{caID}},
	}

	if queryParams == nil {
		return db.readQuerier.Count(ctx, opts)
	}

	return db.readQuerier.CountFiltered(ctx, queryParams.Filters, opts)
}

func (db *PostgresCertificateStorage) CountByCAIDAndStatus(ctx context.Context, caID string, status models.CertificateStatus) (int, error) {
	opts := []GormExtraOps{
		{Query: "issuer_meta_id = ?", AdditionalWhere: []any{caID}},
		{Query: "status = ?", AdditionalWhere: []any{status}},
	}
	return db.readQuerier.Count(ctx, opts)
}

func (db *PostgresCertificateStorage) SelectByType(ctx context.Context, CAType models.CertificateType, req storage.StorageListRequest[models.Certificate]) (string, error) {
	opts := []GormExtraOps{
		{Query: "type = ?", AdditionalWhere: []any{CAType}},
	}
	return db.readQuerier.SelectAll(ctx, req.QueryParams, opts, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *PostgresCertificateStorage) SelectAll(ctx context.Context, req storage.StorageListRequest[models.Certificate]) (string, error) {
	return db.readQuerier.SelectAll(ctx, req.QueryParams, []GormExtraOps{}, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *PostgresCertificateStorage) SelectExistsBySerialNumber(ctx context.Context, id string) (bool, *models.Certificate, error) {
	return db.readQuerier.SelectExists(ctx, id, nil)
}

func (db *PostgresCertificateStorage) Insert(ctx context.Context, certificate *models.Certificate) (*models.Certificate, error) {
	inserted, err := db.querier.Insert(ctx, certificate, certificate.SerialNumber)
	if isCertificateKeyViolation(err) {
		return nil, errs.ErrKeyNotFound
	}
	if err != nil {
		return nil, err
	}
	return db.reload(ctx, inserted)
}

func (db *PostgresCertificateStorage) Update(ctx context.Context, certificate *models.Certificate) (*models.Certificate, error) {
	updated, err := db.querier.Update(ctx, certificate, certificate.SerialNumber)
	if err != nil {
		return nil, err
	}
	return db.reload(ctx, updated)
}

// reload returns the persisted representation, including fields derived by the view.
func (db *PostgresCertificateStorage) reload(ctx context.Context, certificate *models.Certificate) (*models.Certificate, error) {
	found, stored, err := db.SelectExistsBySerialNumber(ctx, certificate.SerialNumber)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, gorm.ErrRecordNotFound
	}
	*certificate = *stored
	return certificate, nil
}

func (db *PostgresCertificateStorage) Delete(ctx context.Context, serialNumber string) error {
	err := db.querier.Delete(ctx, serialNumber)
	if isForeignKeyViolation(err, "va_role_signer_certificate_fk") {
		return errs.ErrCertificateInUse
	}
	return err
}

func (db *PostgresCertificateStorage) ReleaseKey(ctx context.Context, serialNumbers []string) error {
	if len(serialNumbers) == 0 {
		return nil
	}

	return db.db.WithContext(ctx).Table("certificates").Where("serial_number IN ?", serialNumbers).Update("key_id", nil).Error
}

func (db *PostgresCertificateStorage) SelectByCA(ctx context.Context, caID string, req storage.StorageListRequest[models.Certificate]) (string, error) {
	opts := []GormExtraOps{
		{Query: "issuer_meta_id = ?", AdditionalWhere: []any{caID}},
	}
	return db.readQuerier.SelectAll(ctx, req.QueryParams, opts, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *PostgresCertificateStorage) SelectByExpirationDate(ctx context.Context, beforeExpirationDate time.Time, afterExpirationDate time.Time, req storage.StorageListRequest[models.Certificate]) (string, error) {
	opts := []GormExtraOps{
		{Query: "valid_to > ?", AdditionalWhere: []any{afterExpirationDate}},
		{Query: "valid_to < ?", AdditionalWhere: []any{beforeExpirationDate}},
		{Query: "status != ?", AdditionalWhere: []any{models.StatusExpired}},
		{Query: "status != ?", AdditionalWhere: []any{models.StatusRevoked}},
	}

	return db.readQuerier.SelectAll(ctx, req.QueryParams, opts, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *PostgresCertificateStorage) SelectByCAIDAndStatus(ctx context.Context, CAID string, status models.CertificateStatus, req storage.StorageListRequest[models.Certificate]) (string, error) {
	opts := []GormExtraOps{
		{Query: "status = ?", AdditionalWhere: []any{status}},
		{Query: "issuer_meta_id = ?", AdditionalWhere: []any{CAID}},
	}

	return db.readQuerier.SelectAll(ctx, req.QueryParams, opts, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *PostgresCertificateStorage) SelectByStatus(ctx context.Context, status models.CertificateStatus, req storage.StorageListRequest[models.Certificate]) (string, error) {
	opts := []GormExtraOps{
		{Query: "status = ?", AdditionalWhere: []any{status}},
	}

	return db.readQuerier.SelectAll(ctx, req.QueryParams, opts, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *PostgresCertificateStorage) CountByCA(ctx context.Context, CAID string) (int, error) {
	return db.readQuerier.Count(ctx, []GormExtraOps{
		{Query: "issuer_meta_id = ?", AdditionalWhere: []any{CAID}},
	})
}
