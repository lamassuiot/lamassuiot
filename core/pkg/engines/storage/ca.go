package storage

import (
	"context"
	"time"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
)

type CertificatesRepo interface {
	CountByCA(ctx context.Context, caID string) (int, error)
	CountByCAIDAndStatus(ctx context.Context, caID string, status models.CertificateStatus) (int, error)
	SelectByCA(ctx context.Context, caID string, req StorageListRequest[models.Certificate]) (string, error)
	SelectByExpirationDate(ctx context.Context, beforeExpirationDate time.Time, afterExpirationDate time.Time, req StorageListRequest[models.Certificate]) (string, error)
	SelectByCAIDAndStatus(ctx context.Context, CAID string, status models.CertificateStatus, req StorageListRequest[models.Certificate]) (string, error)
	SelectByStatus(ctx context.Context, status models.CertificateStatus, req StorageListRequest[models.Certificate]) (string, error)

	Count(ctx context.Context) (int, error)
	CountWithFilters(ctx context.Context, queryParams *resources.QueryParameters) (int, error)
	CountByCAIDWithFilters(ctx context.Context, caID string, queryParams *resources.QueryParameters) (int, error)
	SelectAll(ctx context.Context, req StorageListRequest[models.Certificate]) (string, error)
	SelectExistsBySerialNumber(ctx context.Context, serialNumber string) (bool, *models.Certificate, error)
	Update(ctx context.Context, certificate *models.Certificate) (*models.Certificate, error)
	Insert(ctx context.Context, certificate *models.Certificate) (*models.Certificate, error)
	Delete(ctx context.Context, serialNumber string) error
}

type CACertificatesRepo interface {
	SelectByType(ctx context.Context, CAType models.CertificateType, req StorageListRequest[models.CACertificate]) (string, error)
	Count(ctx context.Context) (int, error)
	CountWithFilters(ctx context.Context, queryParams *resources.QueryParameters) (int, error)
	CountByEngine(ctx context.Context, engineID string) (int, error)
	CountByEngineWithFilters(ctx context.Context, engineID string, queryParams *resources.QueryParameters) (int, error)
	CountByStatus(ctx context.Context, status models.CertificateStatus) (int, error)
	SelectAll(ctx context.Context, req StorageListRequest[models.CACertificate]) (string, error)

	SelectExistsByID(ctx context.Context, id string) (bool, *models.CACertificate, error)
	SelectExistsBySerialNumber(ctx context.Context, serialNumber string) (bool, *models.CACertificate, error)
	SelectByCommonName(ctx context.Context, commonName string, req StorageListRequest[models.CACertificate]) (string, error)
	SelectByParentCA(ctx context.Context, parentCAID string, req StorageListRequest[models.CACertificate]) (string, error)
	SelectBySubjectAndSubjectKeyID(ctx context.Context, sub models.Subject, skid string, req StorageListRequest[models.CACertificate]) (string, error)
	SelectByIssuerAndAuthorityKeyID(ctx context.Context, iss models.Subject, akid string, req StorageListRequest[models.CACertificate]) (string, error)

	Insert(ctx context.Context, caCertificate *models.CACertificate) (*models.CACertificate, error)
	Update(ctx context.Context, caCertificate *models.CACertificate) (*models.CACertificate, error)
	Delete(ctx context.Context, caID string) error
}

type IssuanceProfileRepo interface {
	Count(ctx context.Context) (int, error)
	SelectAll(ctx context.Context, req StorageListRequest[models.IssuanceProfile]) (string, error)
	SelectByID(ctx context.Context, id string) (bool, *models.IssuanceProfile, error)
	Insert(ctx context.Context, issuanceProfile *models.IssuanceProfile) (*models.IssuanceProfile, error)
	Update(ctx context.Context, issuanceProfile *models.IssuanceProfile) (*models.IssuanceProfile, error)
	Delete(ctx context.Context, id string) error
}
