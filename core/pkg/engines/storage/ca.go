package storage

import (
	"context"
	"time"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
)

type CertificatesRepo interface {
	CountByCA(ctx context.Context, caID string) (int, error)
	CountByCAIDAndStatus(ctx context.Context, caID string, status models.CertificateStatus) (int, error)
	SelectByCA(ctx context.Context, caID string, req StorageListRequest[models.Certificate]) (string, error)
	SelectByExpirationDate(ctx context.Context, beforeExpirationDate time.Time, afterExpirationDate time.Time, req StorageListRequest[models.Certificate]) (string, error)
	SelectByCAIDAndStatus(ctx context.Context, CAID string, status models.CertificateStatus, req StorageListRequest[models.Certificate]) (string, error)
	SelectByStatus(ctx context.Context, status models.CertificateStatus, req StorageListRequest[models.Certificate]) (string, error)

	Count(ctx context.Context) (int, error)
	SelectAll(ctx context.Context, req StorageListRequest[models.Certificate]) (string, error)
	SelectExistsBySerialNumber(ctx context.Context, serialNumber string) (bool, *models.Certificate, error)
	Update(ctx context.Context, certificate *models.Certificate) (*models.Certificate, error)
	Insert(ctx context.Context, certificate *models.Certificate) (*models.Certificate, error)

	SelectExistsCAByID(ctx context.Context, id string) (bool, *models.Certificate, error)
	SelectExistsCABySerialNumber(ctx context.Context, serialNumber string) (bool, *models.Certificate, error)
	SelectCAByCommonName(ctx context.Context, commonName string, req StorageListRequest[models.Certificate]) (string, error)
	SelectCAByParentCA(ctx context.Context, parentCAID string, req StorageListRequest[models.Certificate]) (string, error)
	SelectAllCA(ctx context.Context, req StorageListRequest[models.Certificate]) (string, error)
	DeleteCA(ctx context.Context, caID string) error
	CountCA(ctx context.Context) (int, error)
	CountCAByEngine(ctx context.Context, engineID string) (int, error)
	CountCAByStatus(ctx context.Context, status models.CertificateStatus) (int, error)
	SelectCAByIssuerAndAuthorityKeyID(ctx context.Context, iss models.Subject, akid string, req StorageListRequest[models.Certificate]) (string, error)
	SelectCABySubjectAndSubjectKeyID(ctx context.Context, sub models.Subject, skid string, req StorageListRequest[models.Certificate]) (string, error)
}

type CACertificateRequestRepo interface {
	Insert(ctx context.Context, caCertificateRequest *models.CACertificateRequest) (*models.CACertificateRequest, error)
	SelectExistsByID(ctx context.Context, id string) (bool, *models.CACertificateRequest, error)
	SelectAll(ctx context.Context, req StorageListRequest[models.CACertificateRequest]) (string, error)
	SelectByFingerprint(ctx context.Context, fingerprint string, req StorageListRequest[models.CACertificateRequest]) (string, error)
	Update(ctx context.Context, caCertificate *models.CACertificateRequest) (*models.CACertificateRequest, error)
	Delete(ctx context.Context, caID string) error
}
