package storage

import (
	"context"
	"time"

	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/lamassuiot/lamassuiot/pkg/v3/resources"
)

type CertificatesRepo interface {
	CountByCA(ctx context.Context, caID string) (int, error)
	SelectByCA(ctx context.Context, caID string, exhaustiveRun bool, applyFunc func(*models.Certificate), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error)
	SelectByExpirationDate(ctx context.Context, beforeExpirationDate time.Time, afterExpirationDate time.Time, exhaustiveRun bool, applyFunc func(*models.Certificate), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error)

	Count(ctx context.Context) (int, error)
	Exists(ctx context.Context, sn string) (bool, error)
	SelectAll(ctx context.Context, exhaustiveRun bool, applyFunc func(*models.Certificate), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error)
	Select(ctx context.Context, serialNumber string) (*models.Certificate, error)
	Update(ctx context.Context, certificate *models.Certificate) (*models.Certificate, error)
	Insert(ctx context.Context, certificate *models.Certificate) (*models.Certificate, error)
}

type CACertificatesRepo interface {
	Exists(ctx context.Context, caID string) (bool, error)
	SelectByType(ctx context.Context, CAType models.CAType, exhaustiveRun bool, applyFunc func(*models.CACertificate), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error)

	Count(ctx context.Context) (int, error)
	SelectAll(ctx context.Context, exhaustiveRun bool, applyFunc func(*models.CACertificate), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error)
	Select(ctx context.Context, id string) (*models.CACertificate, error)
	Insert(ctx context.Context, caCertificate *models.CACertificate) (*models.CACertificate, error)
	Update(ctx context.Context, caCertificate *models.CACertificate) (*models.CACertificate, error)
}
