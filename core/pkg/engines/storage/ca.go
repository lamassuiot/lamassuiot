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
}

type CACertificatesRepo interface {
	SelectByType(ctx context.Context, CAType models.CertificateType, req StorageListRequest[models.CACertificate]) (string, error)
	Count(ctx context.Context) (int, error)
	CountByEngine(ctx context.Context, engineID string) (int, error)
	CountByStatus(ctx context.Context, status models.CertificateStatus) (int, error)
	SelectAll(ctx context.Context, req StorageListRequest[models.CACertificate]) (string, error)

	SelectExistsByID(ctx context.Context, id string) (bool, *models.CACertificate, error)
	SelectExistsBySerialNumber(ctx context.Context, serialNumber string) (bool, *models.CACertificate, error)
	SelectByCommonName(ctx context.Context, commonName string, req StorageListRequest[models.CACertificate]) (string, error)
	SelectByParentCA(ctx context.Context, parentCAID string, req StorageListRequest[models.CACertificate]) (string, error)

	Insert(ctx context.Context, caCertificate *models.CACertificate) (*models.CACertificate, error)
	Update(ctx context.Context, caCertificate *models.CACertificate) (*models.CACertificate, error)
	Delete(ctx context.Context, caID string) error
}

type CACertificateRequestRepo interface {
	Insert(ctx context.Context, caCertificateRequest *models.CACertificateRequest) (*models.CACertificateRequest, error)
	SelectExistsByID(ctx context.Context, id string) (bool, *models.CACertificateRequest, error)
	SelectAll(ctx context.Context, req StorageListRequest[models.CACertificateRequest]) (string, error)
	SelectByFingerprint(ctx context.Context, fingerprint string, req StorageListRequest[models.CACertificateRequest]) (string, error)
	Update(ctx context.Context, caCertificate *models.CACertificateRequest) (*models.CACertificateRequest, error)
	Delete(ctx context.Context, caID string) error
}
